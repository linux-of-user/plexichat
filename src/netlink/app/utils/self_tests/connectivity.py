# app/utils/self_tests/connectivity.py
"""
Enhanced connectivity tests with comprehensive error handling and reporting.
Tests IPv4, IPv6, HTTP, DNS, and database host connectivity.
"""

import socket
import requests
from datetime import datetime
from typing import Dict, Any
from urllib.parse import urlparse

from app.logger_config import settings, selftest_logger
from app.utils.self_tests.test_executor import with_retry, with_timeout


class ConnectivityTests:
    """Comprehensive connectivity test suite."""

    def __init__(self):
        self.timeout = settings.CONNECTIVITY_TIMEOUT
        self.logger = selftest_logger

    @with_retry(max_retries=2, delay_seconds=1)
    @with_timeout(10)
    def test_ipv4_connectivity(self) -> Dict[str, Any]:
        """Test IPv4 connectivity to Google DNS."""
        try:
            sock = socket.create_connection(("8.8.8.8", 53), timeout=self.timeout)
            sock.close()
            self.logger.debug("IPv4 connectivity test passed: 8.8.8.8:53")
            return {"ok": True, "detail": "8.8.8.8:53", "target": "Google DNS"}
        except Exception as e:
            self.logger.warning("IPv4 connectivity test failed: %s", e)
            return {"ok": False, "detail": str(e), "target": "Google DNS"}

    @with_retry(max_retries=2, delay_seconds=1)
    @with_timeout(10)
    def test_ipv6_connectivity(self) -> Dict[str, Any]:
        """Test IPv6 connectivity to Google."""
        try:
            info = socket.getaddrinfo("ipv6.google.com", 80, socket.AF_INET6)
            if not info:
                raise Exception("No IPv6 address found")

            addr = info[0][4][0]
            s6 = socket.socket(socket.AF_INET6)
            s6.settimeout(self.timeout)
            s6.connect((addr, 80))
            s6.close()

            self.logger.debug("IPv6 connectivity test passed: %s", addr)
            return {"ok": True, "detail": f"{addr}:80", "target": "Google IPv6"}
        except Exception as e:
            self.logger.warning("IPv6 connectivity test failed: %s", e)
            return {"ok": False, "detail": str(e), "target": "Google IPv6"}

    @with_retry(max_retries=2, delay_seconds=1)
    @with_timeout(15)
    def test_http_connectivity(self) -> Dict[str, Any]:
        """Test HTTP connectivity to external site."""
        try:
            response = requests.get(
                "https://httpbin.org/status/200",
                timeout=self.timeout,
                headers={"User-Agent": "ChatAPI-SelfTest/1.0"}
            )

            self.logger.debug("HTTP connectivity test: %s", response.status_code)
            return {
                "ok": response.ok,
                "detail": f"Status: {response.status_code}",
                "target": "httpbin.org",
                "response_time_ms": response.elapsed.total_seconds() * 1000
            }
        except Exception as e:
            self.logger.warning("HTTP connectivity test failed: %s", e)
            return {"ok": False, "detail": str(e), "target": "httpbin.org"}

    @with_retry(max_retries=2, delay_seconds=1)
    @with_timeout(10)
    def test_dns_resolution(self) -> Dict[str, Any]:
        """Test DNS resolution for various hosts."""
        test_hosts = [
            "google.com",
            "github.com",
            "httpbin.org"
        ]

        results = {}
        all_ok = True

        for host in test_hosts:
            try:
                ip = socket.gethostbyname(host)
                results[host] = {"ok": True, "ip": ip}
                self.logger.debug("DNS resolution for %s: %s", host, ip)
            except Exception as e:
                results[host] = {"ok": False, "error": str(e)}
                all_ok = False
                self.logger.warning("DNS resolution failed for %s: %s", host, e)

        return {
            "ok": all_ok,
            "detail": f"Resolved {sum(1 for r in results.values() if r['ok'])}/{len(test_hosts)} hosts",
            "results": results
        }

    @with_retry(max_retries=2, delay_seconds=1)
    @with_timeout(10)
    def test_database_host_connectivity(self) -> Dict[str, Any]:
        """Test connectivity to database host."""
        try:
            # Parse database URL to get host and port
            if settings.DB_HOST:
                host = settings.DB_HOST
                port = int(settings.DB_PORT) if settings.DB_PORT else 5432
            else:
                # Parse from DATABASE_URL
                parsed = urlparse(settings.DATABASE_URL)
                host = parsed.hostname
                port = parsed.port or 5432

            if not host:
                raise Exception("No database host configured")

            # Test TCP connection
            sock = socket.create_connection((host, port), timeout=self.timeout)
            sock.close()

            self.logger.debug("Database host connectivity test passed: %s:%d", host, port)
            return {
                "ok": True,
                "detail": f"{host}:{port}",
                "target": "Database Host"
            }
        except Exception as e:
            self.logger.warning("Database host connectivity test failed: %s", e)
            return {
                "ok": False,
                "detail": str(e),
                "target": "Database Host"
            }

    @with_timeout(5)
    def test_local_server_connectivity(self) -> Dict[str, Any]:
        """Test connectivity to local server."""
        try:
            response = requests.get(
                f"{settings.BASE_URL}/v1/status/health",
                timeout=self.timeout
            )

            self.logger.debug("Local server connectivity test: %s", response.status_code)
            return {
                "ok": response.ok,
                "detail": f"Status: {response.status_code}",
                "target": "Local Server",
                "response_time_ms": response.elapsed.total_seconds() * 1000
            }
        except Exception as e:
            self.logger.warning("Local server connectivity test failed: %s", e)
            return {"ok": False, "detail": str(e), "target": "Local Server"}


def run_connectivity_tests() -> Dict[str, Any]:
    """Run all connectivity tests and return results."""
    tests = ConnectivityTests()

    test_functions = {
        "ipv4": tests.test_ipv4_connectivity,
        "ipv6": tests.test_ipv6_connectivity,
        "http": tests.test_http_connectivity,
        "dns": tests.test_dns_resolution,
        "database_host": tests.test_database_host_connectivity,
        "local_server": tests.test_local_server_connectivity
    }

    results = {}
    for test_name, test_func in test_functions.items():
        try:
            results[test_name] = test_func()
        except Exception as e:
            selftest_logger.error("Connectivity test %s failed: %s", test_name, e)
            results[test_name] = {"ok": False, "detail": str(e)}

    # Calculate overall status
    passed_tests = sum(1 for result in results.values() if result.get("ok", False))
    total_tests = len(results)

    selftest_logger.info("Connectivity tests completed: %d/%d passed", passed_tests, total_tests)

    return results
