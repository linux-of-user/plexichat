import sys
import os
from pathlib import Path
import importlib

def run_tests():
    """Run all core, integration, and performance tests from the old test suite."""
    test_dir = Path(__file__).parent.parent / 'src' / 'plexichat' / 'tests'
    sys.path.insert(0, str(test_dir.parent))
    test_modules = [
        'test_api_endpoints',
        'test_features',
        'test_integration',
        'test_performance',
        'test_runner',
        'test_security',
        'legacy_curl_tests',
        'test_update_system',
        'unified_test_manager',
    ]
    results = {}
    for mod in test_modules:
        try:
            m = importlib.import_module(f'plexichat.tests.{mod}')
            if hasattr(m, 'main'):
                print(f'Running {mod}.main()...')
                m.main()
            elif hasattr(m, 'run_tests'):
                print(f'Running {mod}.run_tests()...')
                m.run_tests()
            else:
                print(f'Imported {mod}, but no main() or run_tests() found.')
            results[mod] = 'OK'
        except Exception as e:
            print(f'Error running {mod}: {e}')
            results[mod] = f'ERROR: {e}'
    return results

if __name__ == '__main__':
    run_tests() 