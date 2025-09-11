# Developer Guide - PlexiChat Phase H

**Version:** 1.0
**Date:** 2025-08-31
**Target Audience:** New Engineers
**Goal:** 100% green tests + CI in <1 hour

## Welcome to PlexiChat

Welcome to the PlexiChat development team! This guide will help you get up and running quickly with our enterprise-grade communication platform. By following this guide, you'll be able to achieve 100% green tests and CI within 1 hour.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Project Structure](#project-structure)
4. [Development Workflow](#development-workflow)
5. [Testing Strategy](#testing-strategy)
6. [Code Quality Standards](#code-quality-standards)
7. [Security Guidelines](#security-guidelines)
8. [Deployment Process](#deployment-process)
9. [Troubleshooting](#troubleshooting)
10. [Resources](#resources)

## Prerequisites

### System Requirements
- **Operating System:** Windows 11, macOS 12+, or Ubuntu 20.04+
- **RAM:** 8GB minimum, 16GB recommended
- **Disk Space:** 10GB free space
- **Network:** Stable internet connection

### Required Software
```bash
# Core development tools
Python 3.8+ (https://python.org)
Git (https://git-scm.com)
Docker Desktop (https://docker.com)
VS Code (https://code.visualstudio.com)

# Database
PostgreSQL 13+ (https://postgresql.org)
Redis 6+ (https://redis.io)

# Optional but recommended
Node.js 16+ (for frontend development)
kubectl (for Kubernetes deployments)
```

### Development Tools
```bash
# Python package manager
pip install --upgrade pip

# Virtual environment
pip install virtualenv

# Code quality tools
pip install black flake8 mypy bandit

# Testing framework
pip install pytest pytest-cov pytest-xdist

# Documentation
pip install sphinx mkdocs
```

## Environment Setup

### Step 1: Clone the Repository
```bash
# Clone the main repository
git clone https://github.com/plexichat/plexichat.git
cd plexichat

# Clone submodules if any
git submodule update --init --recursive
```

### Step 2: Set Up Python Environment
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### Step 3: Database Setup
```bash
# Install PostgreSQL (Ubuntu/Debian)
sudo apt update
sudo apt install postgresql postgresql-contrib

# Install PostgreSQL (macOS with Homebrew)
brew install postgresql
brew services start postgresql

# Create database
createdb plexichat_dev

# Set up database user
createuser plexichat_user --createdb --login
psql -c "ALTER USER plexichat_user PASSWORD 'secure_password';"
```

### Step 4: Redis Setup
```bash
# Install Redis (Ubuntu/Debian)
sudo apt install redis-server
sudo systemctl start redis-server

# Install Redis (macOS with Homebrew)
brew install redis
brew services start redis

# Verify Redis is running
redis-cli ping
```

### Step 5: Configuration
```bash
# Copy configuration template
cp config.example.yaml config.yaml

# Edit configuration with your settings
# Database connection
DATABASE_URL=postgresql://plexichat_user:secure_password@localhost/plexichat_dev

# Redis connection
REDIS_URL=redis://localhost:6379

# Application settings
SECRET_KEY=your-secret-key-here
DEBUG=True
```

### Step 6: Run Initial Setup
```bash
# Run database migrations
alembic upgrade head

# Create initial data
python scripts/setup_initial_data.py

# Verify setup
python -c "import plexichat; print('Setup successful!')"
```

## Project Structure

```
plexichat/
├── src/plexichat/              # Main application code
│   ├── core/                   # Core functionality
│   │   ├── auth/              # Authentication system
│   │   ├── database/          # Database layer
│   │   ├── security/          # Security components
│   │   └── logging/           # Logging system
│   ├── features/              # Feature modules
│   │   ├── ai/                # AI integration
│   │   ├── backup/            # Backup system
│   │   ├── clustering/        # Clustering support
│   │   └── messaging/         # Messaging features
│   ├── interfaces/            # Interface layers
│   │   ├── api/               # REST API
│   │   ├── web/               # Web interface
│   │   └── cli/               # Command-line interface
│   └── plugins/               # Plugin system
├── tests/                     # Test suite
│   ├── unit/                  # Unit tests
│   ├── integration/           # Integration tests
│   ├── e2e/                   # End-to-end tests
│   └── security/              # Security tests
├── docs/                      # Documentation
├── scripts/                   # Utility scripts
├── config/                    # Configuration files
├── docker/                    # Docker files
└── kubernetes/                # Kubernetes manifests
```

## Development Workflow

### Daily Development Cycle

#### 1. Start Your Day
```bash
# Pull latest changes
git pull origin main

# Activate virtual environment
source venv/bin/activate

# Run tests to ensure everything is working
pytest tests/unit/ -v

# Start development server
python -m plexichat runserver
```

#### 2. Create a Feature Branch
```bash
# Create feature branch
git checkout -b feature/your-feature-name

# Make your changes
# Write code, add tests, update documentation
```

#### 3. Code Development
```bash
# Run code quality checks
black .  # Format code
flake8 .  # Lint code
mypy .    # Type check

# Run tests
pytest tests/unit/test_your_feature.py -v

# Run integration tests
pytest tests/integration/ -v
```

#### 4. Commit Your Changes
```bash
# Add your changes
git add .

# Commit with descriptive message
git commit -m "feat: add user authentication feature

- Implement JWT token authentication
- Add user registration endpoint
- Add password hashing with bcrypt
- Add input validation

Closes #123"

# Push to remote
git push origin feature/your-feature-name
```

#### 5. Create Pull Request
```bash
# Create pull request on GitHub/GitLab
# Add description, link to issues
# Request review from team members
```

### Code Review Process

#### Reviewer Checklist
- [ ] Code follows style guidelines
- [ ] Tests are comprehensive and passing
- [ ] Documentation is updated
- [ ] Security considerations addressed
- [ ] Performance implications reviewed
- [ ] Database migrations included if needed

#### Author Checklist
- [ ] All tests pass locally
- [ ] Code is properly formatted
- [ ] Documentation updated
- [ ] Migration scripts tested
- [ ] Breaking changes documented

## Testing Strategy

### Test Pyramid
```
End-to-End Tests (5-10%)
├── User journey tests
└── Integration workflows

Integration Tests (20-30%)
├── API endpoint tests
├── Database integration
└── External service integration

Unit Tests (60-70%)
├── Function tests
├── Class tests
├── Utility tests
└── Mocked dependency tests
```

### Running Tests

#### Unit Tests
```bash
# Run all unit tests
pytest tests/unit/ -v

# Run specific test file
pytest tests/unit/test_authentication.py -v

# Run with coverage
pytest tests/unit/ --cov=src/plexichat --cov-report=html

# Run specific test function
pytest tests/unit/test_authentication.py::test_login_success -v
```

#### Integration Tests
```bash
# Run integration tests
pytest tests/integration/ -v

# Run with database
pytest tests/integration/ --db-url=postgresql://test:test@localhost/test_db

# Run API tests
pytest tests/integration/test_api_endpoints.py -v
```

#### End-to-End Tests
```bash
# Run E2E tests
pytest tests/e2e/ -v

# Run with browser
pytest tests/e2e/test_user_registration.py --browser=chrome

# Run specific user journey
pytest tests/e2e/test_complete_user_workflow.py -v
```

#### Security Tests
```bash
# Run security tests
pytest tests/security/ -v

# Run vulnerability scans
bandit -r src/plexichat/

# Run dependency checks
safety check
```

### Test Coverage Goals
- **Unit Tests:** 80%+ coverage
- **Integration Tests:** 70%+ coverage
- **End-to-End Tests:** 60%+ coverage
- **Overall Coverage:** 75%+ coverage

### Writing Tests

#### Unit Test Example
```python
import pytest
from unittest.mock import Mock, patch
from plexichat.core.auth.services import AuthenticationService

class TestAuthenticationService:
    
    def setup_method(self):
        """Set up test fixtures"""
        self.auth_service = AuthenticationService()
        self.mock_user_repo = Mock()
        self.auth_service.user_repository = self.mock_user_repo
    
    def test_authenticate_valid_credentials(self):
        """Test successful authentication"""
        # Arrange
        username = "testuser"
        password = "correct_password"
        expected_user = Mock(id=1, username=username)
        
        self.mock_user_repo.get_by_username.return_value = expected_user
        self.mock_user_repo.verify_password.return_value = True
        
        # Act
        result = self.auth_service.authenticate(username, password)
        
        # Assert
        assert result is not None
        assert result.id == 1
        assert result.username == username
        self.mock_user_repo.get_by_username.assert_called_once_with(username)
        self.mock_user_repo.verify_password.assert_called_once()
    
    def test_authenticate_invalid_credentials(self):
        """Test authentication with invalid credentials"""
        # Arrange
        username = "testuser"
        password = "wrong_password"
        
        self.mock_user_repo.get_by_username.return_value = None
        
        # Act & Assert
        with pytest.raises(AuthenticationError):
            self.auth_service.authenticate(username, password)
```

#### Integration Test Example
```python
import pytest
from fastapi.testclient import TestClient
from plexichat.interfaces.api.main import app

class TestUserAPI:
    
    def setup_method(self):
        """Set up test client and database"""
        self.client = TestClient(app)
        # Set up test database
        # Clean up data
    
    def teardown_method(self):
        """Clean up after tests"""
        # Clean up test data
        pass
    
    def test_create_user_success(self):
        """Test successful user creation"""
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "secure_password123"
        }
        
        response = self.client.post("/api/v1/users", json=user_data)
        
        assert response.status_code == 201
        data = response.json()
        assert data["user"]["username"] == user_data["username"]
        assert data["user"]["email"] == user_data["email"]
        assert "id" in data["user"]
        assert "password" not in data["user"]  # Password should not be returned
    
    def test_create_user_duplicate_username(self):
        """Test creating user with duplicate username"""
        user_data = {
            "username": "existinguser",
            "email": "test@example.com",
            "password": "secure_password123"
        }
        
        # Create first user
        response1 = self.client.post("/api/v1/users", json=user_data)
        assert response1.status_code == 201
        
        # Try to create duplicate
        response2 = self.client.post("/api/v1/users", json=user_data)
        assert response2.status_code == 409
        assert "username already exists" in response2.json()["error"]["message"]
    
    def test_get_user_profile(self):
        """Test retrieving user profile"""
        # Create user first
        user_data = {
            "username": "profileuser",
            "email": "profile@example.com",
            "password": "secure_password123"
        }
        create_response = self.client.post("/api/v1/users", json=user_data)
        user_id = create_response.json()["user"]["id"]
        
        # Get user profile
        response = self.client.get(f"/api/v1/users/{user_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["user"]["id"] == user_id
        assert data["user"]["username"] == user_data["username"]
```

## Code Quality Standards

### Python Style Guidelines
```python
# Good: Descriptive variable names
user_authentication_service = AuthenticationService()

# Bad: Unclear abbreviations
uas = AuthenticationService()

# Good: Type hints
def authenticate_user(username: str, password: str) -> Optional[User]:
    pass

# Good: Docstrings
def authenticate_user(username: str, password: str) -> Optional[User]:
    """
    Authenticate a user with username and password.
    
    Args:
        username: User's username
        password: User's password (plain text)
    
    Returns:
        User object if authentication successful, None otherwise
    
    Raises:
        AuthenticationError: If authentication fails
    """
    pass

# Good: Error handling
try:
    user = authenticate_user(username, password)
except AuthenticationError as e:
    logger.warning(f"Authentication failed for user {username}: {e}")
    return None
except Exception as e:
    logger.error(f"Unexpected error during authentication: {e}")
    raise

# Bad: Bare except
try:
    user = authenticate_user(username, password)
except:
    return None
```

### Code Formatting
```bash
# Format code with Black
black .

# Static Analysis Setup

PlexiChat uses comprehensive static analysis to maintain code quality. The system includes pre-commit hooks, CI checks, and a custom analysis reporter.

#### Local Setup

1. **Install pre-commit hooks:**
   ```bash
   make install-pre-commit
   # or manually:
   pipx install pre-commit
   pre-commit install
   ```

2. **Run static analysis:**
   ```bash
   make static-check
   ```

#### Git Hooks

Pre-commit hooks automatically run on git commit:
- **Black:** Code formatting (line-length=88)
- **Ruff:** Linting and fixing (E, F, I, ASYNC, C4, N rules)
- **MyPy:** Strict type checking with Cython/Numba support
- **Trailing whitespace:** Clean up whitespace

#### CI Integration

Static analysis runs in CI/CD pipeline:
- **Docker build:** Static checks during dev stage
- **GitHub Actions:** Dedicated `static-check` job before tests
- **Failure thresholds:** 0 errors (E/F), 5 warnings allowed

#### Custom Reporter

The `static_analysis_reporter.py` parses Ruff/MyPy JSON output:

**Features:**
- Counts errors/warnings by severity
- Structured logging with file-level details
- Threshold-based failure (0 errors, 5 warnings)
- Top error file reporting

**Usage:**
```bash
python -m plexichat.infrastructure.utils.static_analysis_reporter ruff.json mypy.json
```

**Configuration:**
- Error threshold: 0 (fail on any E/F errors)
- Warning threshold: 5 (log if exceeded)
- Cython/Numba support via mypy-stubs/

#### Analysis Categories

**Ruff Rules:**
- E: pycodestyle errors (fail)
- F: pyflakes imports (fail)
- I: isort imports (info)
- ASYNC: async/await patterns (warning)
- C4: comprehensions (warning)
- N: Numba/Cython (warning)

**MyPy Configuration:**
- Strict mode enabled
- SQLAlchemy/FastAPI/Cython plugins
- mypy_path: ./mypy-stubs
- ignore_missing_imports for compiled modules

#### Troubleshooting

**Pre-commit issues:**
```bash
# Update hooks
pre-commit autoupdate

# Run manually
pre-commit run --all-files

# Skip temporarily (not recommended)
git commit --no-verify
```

**MyPy Cython errors:**
- Check mypy-stubs/cython.pyi and numba.pyi
- Add type hints to .pyx files
- Use `cdef` types in Cython code

**CI failures:**
- Review GitHub Actions logs
- Check ruff.json/mypy.json outputs
- Fix E/F errors first, then warnings

#### Best Practices

1. **Run locally first:** Always run `make static-check` before commit
2. **Fix errors immediately:** E/F errors must be 0
3. **Cython typing:** Use type annotations in .pyx files
4. **Async patterns:** Follow Ruff ASYNC rules for coroutines
5. **Numba stubs:** Use typed.jit() with explicit types
6. **Review thresholds:** Custom reporter logs top error files

The static analysis system ensures 100% pass rate and catches issues early, maintaining PlexiChat's high code quality standards.

# Check code style with Flake8
flake8 . --max-line-length=88 --extend-ignore=E203,W503

# Type checking with MyPy
mypy . --ignore-missing-imports

# Security linting with Bandit
bandit -r src/plexichat/
```

### Commit Message Standards
```
type(scope): description

[optional body]

[optional footer]

Types:
- feat: New feature
- fix: Bug fix
- docs: Documentation
- style: Code style changes
- refactor: Code refactoring
- test: Testing
- chore: Maintenance

Examples:
feat(auth): add JWT token authentication
fix(api): resolve user creation race condition
docs(readme): update installation instructions
```

## Security Guidelines

### Secure Coding Practices
```python
# Good: Parameterized queries
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Bad: SQL injection vulnerable
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# Good: Password hashing
from passlib.hash import bcrypt
hashed_password = bcrypt.hash(password)

# Good: Input validation
from pydantic import BaseModel, validator

class UserCreateRequest(BaseModel):
    username: str
    email: str
    password: str
    
    @validator('username')
    def username_must_be_valid(cls, v):
        if not v or len(v) < 3:
            raise ValueError('Username must be at least 3 characters')
        return v
    
    @validator('password')
    def password_must_be_strong(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v

# Good: Secure random generation
import secrets
token = secrets.token_urlsafe(32)

# Bad: Insecure random
import random
token = str(random.randint(100000, 999999))
```

### Security Testing
```bash
# Run security tests
pytest tests/security/ -v

# Check for vulnerabilities
safety check

# Scan for secrets
gitleaks detect

# Dependency vulnerability scan
pip-audit
```

## Deployment Process

### Local Development
```bash
# Run development server
python -m plexichat runserver --host=0.0.0.0 --port=8000

# Run with auto-reload
python -m plexichat runserver --reload

# Run with debugger
python -m plexichat runserver --debug
```

### Docker Development
```bash
# Build development image
docker build -t plexichat:dev -f docker/Dockerfile.dev .

# Run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f app

# Run tests in container
docker-compose exec app pytest tests/unit/ -v
```

### Production Deployment
```bash
# Build production image
docker build -t plexichat:latest -f docker/Dockerfile .

# Deploy to Kubernetes
kubectl apply -f kubernetes/

# Check deployment status
kubectl get pods
kubectl get services

# View logs
kubectl logs -f deployment/plexichat
```

### CI/CD Pipeline
```yaml
# .github/workflows/ci.yml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.8'
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install -r requirements-dev.txt
    - name: Run tests
      run: pytest --cov=src/plexichat --cov-report=xml
    - name: Upload coverage
      uses: codecov/codecov-action@v2

  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Security scan
      uses: securecodewarrior/github-action-security-scan@v1

  deploy:
    needs: [test, security]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
    - name: Deploy to production
      run: |
        echo "Deploying to production..."
        # Deployment commands here
```

## Troubleshooting

### Common Issues

#### Database Connection Issues
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check connection
psql -h localhost -U plexichat_user -d plexichat_dev

# Reset database
python scripts/reset_database.py

# Check database logs
tail -f /var/log/postgresql/postgresql-13-main.log
```

#### Redis Connection Issues
```bash
# Check Redis status
redis-cli ping

# Check Redis configuration
redis-cli config get *

# Restart Redis
sudo systemctl restart redis-server

# Clear Redis data
redis-cli FLUSHALL
```

#### Test Failures
```bash
# Run tests with verbose output
pytest tests/unit/ -v -s

# Run specific failing test
pytest tests/unit/test_authentication.py::TestAuthenticationService::test_login_failure -v

# Debug test
pytest tests/unit/test_authentication.py::TestAuthenticationService::test_login_failure -v --pdb

# Check test coverage
pytest --cov=src/plexichat --cov-report=html
open htmlcov/index.html
```

#### Import Errors
```bash
# Check Python path
python -c "import sys; print(sys.path)"

# Install missing dependencies
pip install -r requirements.txt

# Check virtual environment
which python
python -c "import plexichat"

# Reinstall package
pip uninstall plexichat
pip install -e .
```

#### Performance Issues
```bash
# Profile application
python -m cProfile -s time plexichat/main.py

# Check memory usage
python -c "import psutil; print(psutil.virtual_memory())"

# Database query analysis
python scripts/analyze_queries.py

# Check slow logs
tail -f logs/application.log | grep "SLOW"
```

### Getting Help

#### Internal Resources
- **Team Chat:** #dev-help on Slack/Microsoft Teams
- **Documentation:** https://docs.plexichat.com
- **Wiki:** https://wiki.plexichat.com
- **Code Search:** https://github.com/plexichat/plexichat/search

#### External Resources
- **Python Documentation:** https://docs.python.org/3/
- **FastAPI Documentation:** https://fastapi.tiangolo.com/
- **PostgreSQL Documentation:** https://www.postgresql.org/docs/
- **Redis Documentation:** https://redis.io/documentation

## Resources

### Essential Reading
1. [ARCH_overview.md](ARCH_overview.md) - System architecture
2. [PLUGIN_API_REFERENCE.md](PLUGIN_API_REFERENCE.md) - Plugin development
3. [TESTING_STRATEGY.md](TESTING_STRATEGY.md) - Testing approach
4. [SECURITY.md](SECURITY.md) - Security guidelines

### Development Tools
- **VS Code Extensions:**
  - Python (Microsoft)
  - Pylance (Microsoft)
  - Python Docstring Generator
  - GitLens
  - Docker
  - Kubernetes

- **Browser Extensions:**
  - React Developer Tools
  - Redux DevTools
  - JSON Formatter

### Learning Paths
```yaml
beginner:
  - Python basics
  - Git fundamentals
  - REST API concepts
  - Database design

intermediate:
  - FastAPI framework
  - Async programming
  - Docker containers
  - Kubernetes orchestration

advanced:
  - Plugin architecture
  - Security hardening
  - Performance optimization
  - Distributed systems
```

### Key Contacts
- **Tech Lead:** tech-lead@plexichat.com
- **DevOps Team:** devops@plexichat.com
- **Security Team:** security@plexichat.com
- **QA Team:** qa@plexichat.com

### Quick Start Checklist
- [ ] Repository cloned
- [ ] Virtual environment created
- [ ] Dependencies installed
- [ ] Database configured
- [ ] Redis configured
- [ ] Configuration file created
- [ ] Initial setup completed
- [ ] Tests running (green)
- [ ] Development server started
- [ ] Basic API endpoints tested
- [ ] Code formatting configured
- [ ] Git workflow understood

**Congratulations!** You've completed the PlexiChat developer onboarding. You're now ready to contribute to our mission of building the world's most secure and scalable communication platform.

Remember: **Code Quality > Speed**. Always prioritize security, testing, and maintainability in your development work.