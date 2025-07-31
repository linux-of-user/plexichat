# PlexiChat Testing Guide

## Overview

PlexiChat includes a comprehensive testing framework with multiple test categories, automated test execution, and detailed reporting. The testing system is designed to ensure reliability, security, and performance across all components.

## Test Categories

The testing system includes 19 different test categories:

| Category | Description |
|----------|-------------|
| **core** | Core system functionality tests |
| **api** | API endpoint and integration tests |
| **plugins** | Plugin system and functionality tests |
| **integration** | Cross-component integration tests |
| **performance** | Performance and load testing |
| **security** | Security and vulnerability tests |
| **database** | Database connectivity and operations |
| **authentication** | Authentication and authorization |
| **messaging** | Messaging system functionality |
| **files** | File upload and management |
| **websocket** | WebSocket and real-time communication |
| **cli** | CLI system and command tests |
| **gui** | GUI interface tests |
| **webui** | Web UI interface tests |
| **client_settings** | Client settings management |
| **user_management** | User creation and management |
| **stress** | Stress and load testing |
| **regression** | Regression testing suite |
| **smoke** | Basic functionality smoke tests |

## Running Tests

### Basic Test Execution

```bash
# Run all available test categories
python -c "
import asyncio
import sys
sys.path.insert(0, 'src')
from plexichat.tests.unified_test_manager import unified_test_manager

async def run_all_tests():
    print('🧪 Running all test categories...')
    categories = list(unified_test_manager.test_categories.keys())
    results = await unified_test_manager.run_tests(categories, verbose=True)
    
    summary = results.get('summary', {})
    print(f'✅ Tests completed: {summary.get(\"passed\", 0)}/{summary.get(\"total_tests\", 0)} passed')

asyncio.run(run_all_tests())
"
```

### Category-Specific Testing

```bash
# Run smoke tests (basic functionality)
python -c "
import asyncio
import sys
sys.path.insert(0, 'src')
from plexichat.tests.unified_test_manager import unified_test_manager

async def run_smoke_tests():
    results = await unified_test_manager.run_tests(['smoke'], verbose=True)
    summary = results.get('summary', {})
    print(f'✅ Smoke tests: {summary.get(\"passed\", 0)}/{summary.get(\"total_tests\", 0)} passed')

asyncio.run(run_smoke_tests())
"

# Run API tests
python -c "
import asyncio
import sys
sys.path.insert(0, 'src')
from plexichat.tests.unified_test_manager import unified_test_manager

async def run_api_tests():
    results = await unified_test_manager.run_tests(['api'], verbose=True)
    summary = results.get('summary', {})
    print(f'✅ API tests: {summary.get(\"passed\", 0)}/{summary.get(\"total_tests\", 0)} passed')

asyncio.run(run_api_tests())
"

# Run client settings tests
python -c "
import asyncio
import sys
sys.path.insert(0, 'src')
from plexichat.tests.unified_test_manager import unified_test_manager

async def run_client_settings_tests():
    results = await unified_test_manager.run_tests(['client_settings'], verbose=True)
    summary = results.get('summary', {})
    print(f'✅ Client Settings tests: {summary.get(\"passed\", 0)}/{summary.get(\"total_tests\", 0)} passed')

asyncio.run(run_client_settings_tests())
"
```

### Multiple Category Testing

```bash
# Run core functionality tests
python -c "
import asyncio
import sys
sys.path.insert(0, 'src')
from plexichat.tests.unified_test_manager import unified_test_manager

async def run_core_tests():
    categories = ['core', 'api', 'authentication', 'database']
    results = await unified_test_manager.run_tests(categories, verbose=True)
    
    summary = results.get('summary', {})
    print(f'✅ Core tests completed: {summary.get(\"passed\", 0)}/{summary.get(\"total_tests\", 0)} passed')
    
    # Show category breakdown
    for category, result in results.get('category_results', {}).items():
        print(f'  📊 {category}: {result.get(\"passed\", 0)}/{result.get(\"total\", 0)} passed')

asyncio.run(run_core_tests())
"
```

## End-to-End API Testing

### Automated API Testing

```bash
# Run comprehensive API endpoint testing
python -c "
import asyncio
import aiohttp
import json

async def test_api_endpoints():
    base_url = 'http://localhost:8000'
    
    async with aiohttp.ClientSession() as session:
        print('🧪 PlexiChat API End-to-End Testing')
        print('=' * 50)
        
        # Test API Root
        async with session.get(f'{base_url}/api/v1/') as resp:
            data = await resp.json()
            print(f'✅ API Root: {resp.status} - {data.get(\"name\", \"Unknown\")}')
        
        # Test Client Settings
        async with session.get(f'{base_url}/api/v1/client-settings/config/limits') as resp:
            data = await resp.json()
            print(f'✅ Client Settings: {resp.status} - {data.get(\"max_key_value_pairs\", \"N/A\")} max pairs')
        
        # Test Documentation
        async with session.get(f'{base_url}/docs') as resp:
            print(f'✅ Documentation: {resp.status} - Swagger UI available')
        
        print('🚀 All endpoints tested successfully!')

asyncio.run(test_api_endpoints())
"
```

### Manual API Testing

```bash
# Start the API server
python run.py api --port 8000

# In another terminal, test endpoints:

# Test API root
curl -X GET http://localhost:8000/api/v1/

# Test client settings configuration
curl -X GET http://localhost:8000/api/v1/client-settings/config/limits

# Test authentication (should return 403)
curl -X GET http://localhost:8000/api/v1/users/

# Test documentation
curl -X GET http://localhost:8000/docs

# Test OpenAPI schema
curl -X GET http://localhost:8000/openapi.json
```

## Performance Testing

### Load Testing

```bash
# Run performance tests
python -c "
import asyncio
import sys
sys.path.insert(0, 'src')
from plexichat.tests.unified_test_manager import unified_test_manager

async def run_performance_tests():
    categories = ['performance', 'stress']
    results = await unified_test_manager.run_tests(categories, verbose=True)
    
    summary = results.get('summary', {})
    print(f'✅ Performance tests: {summary.get(\"passed\", 0)}/{summary.get(\"total_tests\", 0)} passed')

asyncio.run(run_performance_tests())
"
```

## Security Testing

### Security Validation

```bash
# Run security tests
python -c "
import asyncio
import sys
sys.path.insert(0, 'src')
from plexichat.tests.unified_test_manager import unified_test_manager

async def run_security_tests():
    categories = ['security', 'authentication']
    results = await unified_test_manager.run_tests(categories, verbose=True)
    
    summary = results.get('summary', {})
    print(f'✅ Security tests: {summary.get(\"passed\", 0)}/{summary.get(\"total_tests\", 0)} passed')

asyncio.run(run_security_tests())
"
```

## Continuous Integration

### Pre-Commit Testing

```bash
# Run essential tests before committing
python -c "
import asyncio
import sys
sys.path.insert(0, 'src')
from plexichat.tests.unified_test_manager import unified_test_manager

async def run_pre_commit_tests():
    categories = ['smoke', 'core', 'api', 'security']
    results = await unified_test_manager.run_tests(categories, verbose=True)
    
    summary = results.get('summary', {})
    total_tests = summary.get('total_tests', 0)
    passed_tests = summary.get('passed', 0)
    
    print(f'\\n🎯 Pre-commit Test Summary:')
    print(f'✅ {passed_tests}/{total_tests} tests passed')
    
    if passed_tests == total_tests:
        print('🚀 All tests passed! Ready to commit.')
        exit(0)
    else:
        print('❌ Some tests failed. Please fix before committing.')
        exit(1)

asyncio.run(run_pre_commit_tests())
"
```

### Full Test Suite

```bash
# Run complete test suite (for releases)
python -c "
import asyncio
import sys
sys.path.insert(0, 'src')
from plexichat.tests.unified_test_manager import unified_test_manager

async def run_full_test_suite():
    print('🧪 Running Full Test Suite...')
    print('This may take several minutes...')
    
    all_categories = list(unified_test_manager.test_categories.keys())
    results = await unified_test_manager.run_tests(all_categories, verbose=True, save_report=True)
    
    summary = results.get('summary', {})
    print(f'\\n🎯 Full Test Suite Results:')
    print(f'✅ {summary.get(\"passed\", 0)}/{summary.get(\"total_tests\", 0)} tests passed')
    print(f'❌ {summary.get(\"failed\", 0)} tests failed')
    print(f'⏭️  {summary.get(\"skipped\", 0)} tests skipped')
    
    # Show detailed breakdown
    print(f'\\n📊 Category Breakdown:')
    for category, result in results.get('category_results', {}).items():
        status = '✅' if result.get('failed', 0) == 0 else '❌'
        print(f'  {status} {category}: {result.get(\"passed\", 0)}/{result.get(\"total\", 0)}')

asyncio.run(run_full_test_suite())
"
```

## Test Reports

Test reports are automatically saved to `logs/test_reports/` with timestamps. Reports include:

- Test execution summary
- Category-wise results
- Individual test results
- Performance metrics
- Error details and stack traces

## Best Practices

1. **Run smoke tests** before starting development
2. **Run relevant category tests** during development
3. **Run pre-commit tests** before committing code
4. **Run full test suite** before releases
5. **Monitor test reports** for trends and issues
6. **Update tests** when adding new features
7. **Fix failing tests** immediately

## Troubleshooting

### Common Issues

1. **Server not running**: Start the API server before running API tests
2. **Import errors**: Ensure you're in the correct directory and dependencies are installed
3. **Permission errors**: Check file permissions for log directories
4. **Network errors**: Verify localhost connectivity and port availability

### Debug Mode

Add `verbose=True` to any test execution for detailed output and debugging information.
