# PlexiChat Testing Guide

Comprehensive testing framework for PlexiChat with unified test execution, extensive coverage, and government-level security testing.

## Overview

PlexiChat includes a sophisticated testing framework that combines multiple test types into a unified system:

- **Unit Tests**: Individual component testing
- **Integration Tests**: Component interaction testing  
- **End-to-End Tests**: Complete workflow testing
- **Performance Tests**: Load and performance testing
- **Security Tests**: Vulnerability and penetration testing
- **Unified Test Manager**: Centralized test execution and reporting

## Quick Start

### Running Tests via CLI

```bash
# Run all tests
plexichat test run

# Run specific test categories
plexichat test run --suite security
plexichat test run --suite connectivity
plexichat test run --suite database

# Run health checks
plexichat test health

# Run security tests only
plexichat test security
```

### Running Tests via Python

```bash
# Run unified test suite
python src/plexichat/tests/unified_test_runner.py

# Run with pytest directly
pytest src/plexichat/tests/

# Run specific test categories
pytest src/plexichat/tests/ -m unit
pytest src/plexichat/tests/ -m integration
pytest src/plexichat/tests/ -m security
```

## Test Categories

### 1. System Tests
- Python version compatibility
- File structure validation
- Configuration loading
- Version consistency checks

### 2. Database Tests
- Connection testing
- Schema validation
- Query performance
- Migration testing

### 3. API Tests
- Health endpoint validation
- Authentication testing
- Rate limiting verification
- Response format validation

### 4. Security Tests
- Input validation
- SQL injection protection
- Rate limiting effectiveness
- Authentication security

### 5. Connectivity Tests
- Localhost connectivity
- Port availability
- Network configuration
- Service communication

### 6. Performance Tests
- Load testing
- Memory usage analysis
- Response time measurement
- Concurrent user simulation

## Test Configuration

### Environment Setup

```bash
# Install all dependencies including testing requirements
pip install -r requirements.txt

# Set test environment variables
export PLEXICHAT_TEST_MODE=true
export PLEXICHAT_TEST_DB=sqlite:///test.db
```

### Test Data

Tests use fixtures and mock data located in:
- `src/plexichat/tests/fixtures/` - Test data files
- `src/plexichat/tests/conftest.py` - Pytest fixtures

## Advanced Testing

### Security Testing

```bash
# Run comprehensive security tests
pytest src/plexichat/tests/ -m security

# Run with security scanner
pytest src/plexichat/tests/ -m security --security-scan

# Generate security report
pytest src/plexichat/tests/ -m security --security-report=security_report.json
```

### Performance Testing

```bash
# Run performance tests
pytest src/plexichat/tests/ -m performance

# Run with benchmark output
pytest src/plexichat/tests/ -m performance --benchmark-only

# Memory profiling
pytest src/plexichat/tests/ -m performance --profile
```

### Integration Testing

```bash
# Run integration tests
pytest src/plexichat/tests/integration/

# Test specific integrations
pytest src/plexichat/tests/integration/test_api_integration.py
pytest src/plexichat/tests/integration/test_database_integration.py
```

## Test Results and Reporting

### Unified Test Manager

The unified test manager provides comprehensive reporting:

```python
from src.plexichat.core.testing.unified_test_manager import unified_test_manager

# Run all tests
results = await unified_test_manager.run_all_tests()

# Get test statistics
stats = unified_test_manager.get_test_statistics()

# Get test history
history = unified_test_manager.get_test_history()
```

### Test Output

Tests provide detailed output including:
- Pass/fail status
- Execution time
- Error details
- Performance metrics
- Security findings

Example output:
```
🧪 Running unified tests...
──────────────────────────────────────────────────────

📋 System Tests:
   ✅ Passed: 4
   ❌ Failed: 0
   ⚠️  Warnings: 0
   ⏭️  Skipped: 0
   🕐 Duration: 125ms

📋 Database Tests:
   ✅ Passed: 3
   ❌ Failed: 0
   ⚠️  Warnings: 0
   ⏭️  Skipped: 0
   🕐 Duration: 89ms

──────────────────────────────────────────────────────
🎯 Overall Results: 15/15 passed (100.0%)
🎉 All tests passed!
```

## Continuous Integration

### GitHub Actions

PlexiChat includes GitHub Actions workflows for automated testing:

```yaml
name: PlexiChat Tests
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
          python -m pip install --upgrade pip
          pip install -r requirements.txt
      - name: Run tests
        run: |
          python run.py test
```

### Pre-commit Hooks

Set up pre-commit hooks for automatic testing:

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

## Writing Tests

### Test Structure

```python
import pytest
from src.plexichat.core.testing.unified_test_manager import unified_test_manager

class TestExample:
    """Example test class."""
    
    def test_basic_functionality(self):
        """Test basic functionality."""
        # Arrange
        test_data = {"key": "value"}
        
        # Act
        result = some_function(test_data)
        
        # Assert
        assert result is not None
        assert result["status"] == "success"
    
    @pytest.mark.asyncio
    async def test_async_functionality(self):
        """Test async functionality."""
        result = await some_async_function()
        assert result is not None
```

### Test Markers

Use pytest markers to categorize tests:

```python
@pytest.mark.unit
def test_unit_functionality():
    """Unit test."""
    pass

@pytest.mark.integration
def test_integration_functionality():
    """Integration test."""
    pass

@pytest.mark.security
def test_security_functionality():
    """Security test."""
    pass

@pytest.mark.performance
def test_performance_functionality():
    """Performance test."""
    pass
```

## Troubleshooting

### Common Issues

1. **Test Database Issues**:
   ```bash
   # Reset test database
   rm test.db
   python run.py test
   ```

2. **Port Conflicts**:
   ```bash
   # Check for running services
   netstat -tulpn | grep :8000
   
   # Kill conflicting processes
   pkill -f "python.*plexichat"
   ```

3. **Permission Issues**:
   ```bash
   # Fix file permissions
   chmod +x run.py
   chmod -R 755 src/plexichat/tests/
   ```

### Debug Mode

Run tests in debug mode for detailed output:

```bash
# Enable debug logging
export PLEXICHAT_LOG_LEVEL=DEBUG

# Run tests with verbose output
pytest src/plexichat/tests/ -v -s

# Run with pdb on failure
pytest src/plexichat/tests/ --pdb
```

## Best Practices

1. **Test Isolation**: Each test should be independent
2. **Clear Naming**: Use descriptive test names
3. **Arrange-Act-Assert**: Follow the AAA pattern
4. **Mock External Dependencies**: Use mocks for external services
5. **Test Edge Cases**: Include boundary and error conditions
6. **Performance Awareness**: Monitor test execution time
7. **Security Focus**: Include security-specific test cases

## Related Documentation

- [API Reference](api_reference.md) - API testing endpoints
- [Security Guide](security-guide.md) - Security testing details
- [Admin Guide](admin_deployment_guide.md) - Production testing
- [Installation Guide](installation.md) - Test environment setup
