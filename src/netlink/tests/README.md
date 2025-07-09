# NetLink Testing Framework

Comprehensive testing framework for NetLink with unified test execution, extensive coverage, and government-level security testing.

> **Note**: This documentation has been moved to [docs/testing-guide.md](../../docs/testing-guide.md)

## Overview

This consolidated testing framework combines all NetLink test suites into a unified system with:

- **Unit Tests**: Individual component testing
- **Integration Tests**: Component interaction testing  
- **End-to-End Tests**: Complete workflow testing
- **Performance Tests**: Load and performance testing
- **Security Tests**: Vulnerability and penetration testing

## Directory Structure

```
src/netlink/tests/
├── README.md                           # This file
├── conftest.py                         # Pytest configuration and fixtures
├── requirements.txt                    # Testing dependencies
├── unified_test_runner.py              # Main test runner
├── run_all_tests.py                    # Legacy test runner (updated)
├── test_consolidated_backup_system.py  # Backup system tests
├── test_consolidated_auth_system.py    # Authentication tests
├── unit/                               # Unit tests
├── integration/                        # Integration tests
├── e2e/                               # End-to-end tests
├── performance/                        # Performance tests
├── security/                          # Security tests
└── fixtures/                          # Test data and fixtures
```

## Quick Start

### Install Dependencies

```bash
# Install testing requirements
pip install -r src/netlink/tests/requirements.txt

# Or install with main requirements
pip install -r requirements.txt
```

### Run All Tests

```bash
# Run unified test suite
python src/netlink/tests/unified_test_runner.py

# Run with pytest directly
pytest src/netlink/tests/

# Run specific test categories
pytest src/netlink/tests/ -m unit
pytest src/netlink/tests/ -m integration
pytest src/netlink/tests/ -m security
```

### Run Individual Test Files

```bash
# Run backup system tests
pytest src/netlink/tests/test_consolidated_backup_system.py

# Run authentication tests
pytest src/netlink/tests/test_consolidated_auth_system.py

# Run with coverage
pytest src/netlink/tests/ --cov=src/netlink --cov-report=html
```

## Test Categories

### Unit Tests (`@pytest.mark.unit`)
- Individual component testing
- Mock external dependencies
- Fast execution (< 1 second per test)
- High code coverage focus

### Integration Tests (`@pytest.mark.integration`)
- Component interaction testing
- Real database connections
- File system operations
- Network communication

### End-to-End Tests (`@pytest.mark.e2e`)
- Complete workflow testing
- Full system integration
- User scenario simulation
- API endpoint testing

### Performance Tests (`@pytest.mark.performance`)
- Load testing
- Memory usage monitoring
- Response time validation
- Concurrent operation testing

### Security Tests (`@pytest.mark.security`)
- SQL injection protection
- XSS vulnerability testing
- Authentication security
- Encryption validation
- Access control testing

## Configuration

### Test Configuration (`conftest.py`)

The `conftest.py` file provides comprehensive fixtures:

```python
# Core fixtures
test_config          # Test configuration
temp_directory       # Temporary directories
test_db             # Test database
http_client         # HTTP client for API testing

# Authentication fixtures
test_user           # Test user data
admin_user          # Admin user data
test_token          # JWT tokens
admin_token         # Admin JWT tokens

# Mock services
mock_auth_service   # Mock authentication
mock_backup_service # Mock backup operations
mock_database_service # Mock database operations

# Performance monitoring
performance_monitor # Performance metrics collection

# Security testing
security_scanner    # Vulnerability scanning
```

### Environment Variables

```bash
# Test environment
NETLINK_ENV=testing
NETLINK_DEBUG=true

# Database
NETLINK_DB_URL=sqlite:///:memory:
NETLINK_TEST_DB_URL=sqlite:///test.db

# Security
NETLINK_SECRET_KEY=test_secret_key
NETLINK_ENCRYPTION_KEY=test_encryption_key

# Performance
NETLINK_MAX_RESPONSE_TIME=2.0
NETLINK_MAX_MEMORY_MB=100
```

## Advanced Usage

### Parallel Test Execution

```bash
# Run tests in parallel
pytest src/netlink/tests/ -n auto

# Run with specific worker count
pytest src/netlink/tests/ -n 4
```

### Coverage Reporting

```bash
# Generate HTML coverage report
pytest src/netlink/tests/ --cov=src/netlink --cov-report=html

# Generate XML coverage report (for CI)
pytest src/netlink/tests/ --cov=src/netlink --cov-report=xml

# Coverage with branch analysis
pytest src/netlink/tests/ --cov=src/netlink --cov-branch
```

### Performance Testing

```bash
# Run performance tests only
pytest src/netlink/tests/ -m performance

# Run with benchmark output
pytest src/netlink/tests/ -m performance --benchmark-only

# Memory profiling
pytest src/netlink/tests/ -m performance --profile
```

### Security Testing

```bash
# Run security tests only
pytest src/netlink/tests/ -m security

# Run with security scanner
pytest src/netlink/tests/ -m security --security-scan

# Generate security report
pytest src/netlink/tests/ -m security --security-report=security_report.json
```

## Continuous Integration

### GitHub Actions Integration

The test framework integrates with GitHub Actions:

```yaml
name: NetLink Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          pip install -r src/netlink/tests/requirements.txt
      - name: Run tests
        run: |
          python src/netlink/tests/unified_test_runner.py --ci
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

### Test Reports

The framework generates comprehensive reports:

- **HTML Coverage Report**: `htmlcov/index.html`
- **XML Coverage Report**: `coverage.xml`
- **JSON Test Report**: `test_report.json`
- **Performance Report**: `performance_report.html`
- **Security Report**: `security_report.json`

## Best Practices

### Writing Tests

1. **Use descriptive test names**:
   ```python
   def test_backup_creation_with_government_encryption():
   ```

2. **Follow AAA pattern** (Arrange, Act, Assert):
   ```python
   async def test_user_authentication():
       # Arrange
       credentials = {"username": "test", "password": "pass"}
       
       # Act
       result = await auth_manager.authenticate(credentials)
       
       # Assert
       assert result["success"] is True
   ```

3. **Use appropriate markers**:
   ```python
   @pytest.mark.unit
   @pytest.mark.asyncio
   async def test_password_hashing():
   ```

4. **Mock external dependencies**:
   ```python
   @patch('src.netlink.external_service')
   async def test_with_mocked_service(mock_service):
   ```

### Performance Testing

1. **Set performance thresholds**:
   ```python
   assert response_time < 2.0  # seconds
   assert memory_usage < 100 * 1024 * 1024  # 100MB
   ```

2. **Use performance fixtures**:
   ```python
   def test_performance(performance_monitor):
       performance_monitor.start()
       # ... test code ...
       metrics = performance_monitor.stop()
       assert metrics["duration"] < 5.0
   ```

### Security Testing

1. **Test input validation**:
   ```python
   malicious_inputs = ["'; DROP TABLE users; --", "<script>alert('xss')</script>"]
   for malicious_input in malicious_inputs:
       result = await service.process_input(malicious_input)
       assert result["error"] == "invalid_input"
   ```

2. **Test authentication security**:
   ```python
   # Test brute force protection
   for i in range(10):
       result = await auth.login("user", "wrong_password")
   assert result["error"] == "account_locked"
   ```

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure `src/` is in Python path
2. **Database Errors**: Check test database configuration
3. **Async Errors**: Use `@pytest.mark.asyncio` for async tests
4. **Performance Issues**: Run tests with `--tb=short` for faster feedback

### Debug Mode

```bash
# Run tests in debug mode
pytest src/netlink/tests/ -v -s --tb=long

# Run single test with debugging
pytest src/netlink/tests/test_auth.py::test_login -v -s --pdb
```

### Logging

```bash
# Enable test logging
pytest src/netlink/tests/ --log-cli-level=DEBUG

# Capture logs in reports
pytest src/netlink/tests/ --log-file=test.log
```

## Contributing

1. **Add new tests** to appropriate category directories
2. **Update fixtures** in `conftest.py` for shared test data
3. **Follow naming conventions**: `test_*.py` for test files
4. **Add markers** for test categorization
5. **Update documentation** for new test features

## Support

For issues with the testing framework:

1. Check the test logs: `test.log`
2. Review the coverage report: `htmlcov/index.html`
3. Run tests in debug mode: `pytest -v -s --tb=long`
4. Check GitHub Actions for CI failures
