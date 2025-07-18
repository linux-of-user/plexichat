"""
Performance Tests

Performance and load testing including:
- Response time testing
- Concurrent user simulation
- Database performance
- Memory usage monitoring
- Throughput testing
"""

import asyncio
import concurrent.futures
import logging
import psutil
import requests
import statistics
import time
from typing import Dict, Any, List, Tuple

from . import TestSuite, TestResult, TEST_CONFIG

logger = logging.getLogger(__name__)

class PerformanceTests(TestSuite):
    """Test suite for performance testing."""

    def __init__(self):
        super().__init__("Performance", "performance")
        self.base_url = TEST_CONFIG['base_url']
        self.session = requests.Session()

        # Performance thresholds
        self.thresholds = {
            'response_time_ms': 1000,  # 1 second
            'concurrent_users': 10,
            'memory_usage_mb': 500,
            'cpu_usage_percent': 80
        }

        # Register tests
        self.tests = [
            self.test_response_times,
            self.test_concurrent_requests,
            self.test_database_performance,
            self.test_memory_usage,
            self.test_file_upload_performance,
            self.test_message_throughput,
            self.test_api_scalability,
            self.test_resource_cleanup
        ]

    def make_request(self, method: str, endpoint: str, **kwargs) -> Tuple[requests.Response, float]:
        """Make HTTP request and measure response time."""
        url = f"{self.base_url}{endpoint}"
        start_time = time.time()

        try:
            response = self.session.request(method, url, timeout=TEST_CONFIG['timeout'], **kwargs)
            duration = (time.time() - start_time) * 1000  # Convert to milliseconds
            return response, duration
        except Exception as e:
            duration = (time.time() - start_time) * 1000
            logger.error(f"Request failed: {e}")
            return None, duration

    def test_response_times(self):
        """Test API response times."""
        endpoints = [
            ('GET', '/health'),
            ('GET', '/api/v1/version'),
            ('GET', '/api/v1/messages'),
            ('POST', '/api/v1/messages/create', {'json': {'content': 'test', 'message_type': 'text'}}),
        ]

        response_times = []

        for method, endpoint, *kwargs in endpoints:
            kwargs_dict = kwargs[0] if kwargs else {}

            # Test multiple times for statistical significance
            times = []
            for _ in range(5):
                response, duration = self.make_request(method, endpoint, **kwargs_dict)
                if response:
                    times.append(duration)
                time.sleep(0.1)  # Small delay between requests

            if times:
                avg_time = statistics.mean(times)
                max_time = max(times)
                min_time = min(times)

                response_times.append({)
                    'endpoint': f"{method} {endpoint}",
                    'avg_ms': avg_time,
                    'max_ms': max_time,
                    'min_ms': min_time
                })

                logger.info(f"{method} {endpoint}: avg={avg_time:.2f}ms, max={max_time:.2f}ms")

                # Check against threshold
                if avg_time > self.thresholds['response_time_ms']:
                    logger.warning(f"Slow response time for {endpoint}: {avg_time:.2f}ms")

        # Overall statistics
        if response_times:
            all_avg_times = [rt['avg_ms'] for rt in response_times]
            overall_avg = statistics.mean(all_avg_times)
            logger.info(f"Overall average response time: {overall_avg:.2f}ms")

    def test_concurrent_requests(self):
        """Test concurrent request handling."""
        def make_concurrent_request():
            response, duration = self.make_request('GET', '/health')
            return response.status_code if response else 500, duration

        # Test with increasing concurrency
        concurrency_levels = [1, 5, 10, 20]

        for concurrency in concurrency_levels:
            logger.info(f"Testing with {concurrency} concurrent requests")

            start_time = time.time()

            with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
                futures = [executor.submit(make_concurrent_request) for _ in range(concurrency)]
                results = [future.result() for future in concurrent.futures.as_completed(futures)]

            total_time = time.time() - start_time

            # Analyze results
            successful_requests = sum(1 for status, _ in results if status == 200)
            failed_requests = len(results) - successful_requests
            response_times = [duration for _, duration in results]

            avg_response_time = statistics.mean(response_times) if response_times else 0
            throughput = len(results) / total_time

            logger.info(f"Concurrency {concurrency}: {successful_requests}/{len(results)} successful, ")
                       f"avg response: {avg_response_time:.2f}ms, throughput: {throughput:.2f} req/s")

            if failed_requests > 0:
                logger.warning(f"Failed requests at concurrency {concurrency}: {failed_requests}")

    def test_database_performance(self):
        """Test database performance."""
        # Test multiple database operations
        operations = [
            ('Create messages', 'POST', '/api/v1/messages/create',)
             [{'json': {'content': f'Performance test message {i}', 'message_type': 'text'}}
              for i in range(10)]),
            ('List messages', 'GET', '/api/v1/messages', [{}] * 5),
        ]

        for operation_name, method, endpoint, params_list in operations:
            logger.info(f"Testing {operation_name}")

            times = []
            for params in params_list:
                response, duration = self.make_request(method, endpoint, **params)
                if response and response.status_code in [200, 201]:
                    times.append(duration)

            if times:
                avg_time = statistics.mean(times)
                logger.info(f"{operation_name}: avg={avg_time:.2f}ms over {len(times)} operations")

    def test_memory_usage(self):
        """Test memory usage during operations."""
        try:
            process = psutil.Process()
            initial_memory = process.memory_info().rss / 1024 / 1024  # MB

            logger.info(f"Initial memory usage: {initial_memory:.2f} MB")

            # Perform memory-intensive operations
            for i in range(50):
                large_content = 'A' * 1000  # 1KB message
                data = {'content': large_content, 'message_type': 'text'}
                response, _ = self.make_request('POST', '/api/v1/messages/create', json=data)

                if i % 10 == 0:
                    current_memory = process.memory_info().rss / 1024 / 1024
                    logger.info(f"Memory after {i} operations: {current_memory:.2f} MB")

            final_memory = process.memory_info().rss / 1024 / 1024
            memory_increase = final_memory - initial_memory

            logger.info(f"Final memory usage: {final_memory:.2f} MB (increase: {memory_increase:.2f} MB)")

            if memory_increase > self.thresholds['memory_usage_mb']:
                logger.warning(f"High memory usage increase: {memory_increase:.2f} MB")

        except Exception as e:
            logger.warning(f"Memory monitoring failed: {e}")

    def test_file_upload_performance(self):
        """Test file upload performance."""
        # Create test files of different sizes
        file_sizes = [1024, 10240, 102400]  # 1KB, 10KB, 100KB

        for size in file_sizes:
            # Create test file
            test_content = 'A' * size
            file_path = TEST_CONFIG['temp_dir'] / f'perf_test_{size}.txt'

            with open(file_path, 'w') as f:
                f.write(test_content)

            # Test upload
            with open(file_path, 'rb') as f:
                files = {'file': f}
                response, duration = self.make_request('POST', '/api/v1/files/upload', files=files)

            if response and response.status_code in [200, 201]:
                upload_speed = (size / 1024) / (duration / 1000)  # KB/s
                logger.info(f"File upload {size} bytes: {duration:.2f}ms ({upload_speed:.2f} KB/s)")

            # Cleanup
            file_path.unlink(missing_ok=True)

    def test_message_throughput(self):
        """Test message creation throughput."""
        num_messages = 100
        start_time = time.time()

        successful_creates = 0

        for i in range(num_messages):
            data = {'content': f'Throughput test message {i}', 'message_type': 'text'}
            response, _ = self.make_request('POST', '/api/v1/messages/create', json=data)

            if response and response.status_code in [200, 201]:
                successful_creates += 1

        total_time = time.time() - start_time
        throughput = successful_creates / total_time

        logger.info(f"Message throughput: {throughput:.2f} messages/second ")
                   f"({successful_creates}/{num_messages} successful)")

    def test_api_scalability(self):
        """Test API scalability under load."""
        # Gradually increase load and measure performance degradation
        load_levels = [1, 5, 10, 15, 20]
        results = []

        for load in load_levels:
            logger.info(f"Testing scalability at load level {load}")

            def worker():
                response, duration = self.make_request('GET', '/health')
                return response.status_code if response else 500, duration

            start_time = time.time()

            with concurrent.futures.ThreadPoolExecutor(max_workers=load) as executor:
                futures = [executor.submit(worker) for _ in range(load * 2)]  # 2 requests per worker
                worker_results = [future.result() for future in concurrent.futures.as_completed(futures)]

            total_time = time.time() - start_time

            successful = sum(1 for status, _ in worker_results if status == 200)
            response_times = [duration for _, duration in worker_results]
            avg_response_time = statistics.mean(response_times) if response_times else 0
            throughput = len(worker_results) / total_time

            results.append({)
                'load': load,
                'success_rate': successful / len(worker_results),
                'avg_response_time': avg_response_time,
                'throughput': throughput
            })

            logger.info(f"Load {load}: {successful}/{len(worker_results)} successful, ")
                       f"avg response: {avg_response_time:.2f}ms, throughput: {throughput:.2f} req/s")

        # Analyze scalability
        if len(results) > 1:
            baseline_throughput = results[0]['throughput']
            max_throughput = max(r['throughput'] for r in results)

            logger.info(f"Scalability: baseline={baseline_throughput:.2f} req/s, ")
                       f"max={max_throughput:.2f} req/s")

    def test_resource_cleanup(self):
        """Test resource cleanup and garbage collection."""
        try:
            import gc

            # Force garbage collection
            initial_objects = len(gc.get_objects())

            # Create and destroy many objects
            for i in range(100):
                data = {'content': f'Cleanup test {i}', 'message_type': 'text'}
                response, _ = self.make_request('POST', '/api/v1/messages/create', json=data)

            # Force garbage collection again
            gc.collect()
            final_objects = len(gc.get_objects())

            object_increase = final_objects - initial_objects
            logger.info(f"Object count: initial={initial_objects}, final={final_objects}, ")
                       f"increase={object_increase}")

            if object_increase > 1000:
                logger.warning(f"High object count increase: {object_increase}")

        except Exception as e:
            logger.warning(f"Resource cleanup test failed: {e}")

# Create test suite instance
performance_tests = PerformanceTests()
