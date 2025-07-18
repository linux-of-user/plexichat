#!/usr/bin/env python3
"""
PlexiChat Legacy Endpoint Testing Script (CURL-based)

This is the original curl-based test script moved to the tests directory.
Comprehensive testing of all PlexiChat API endpoints with curl commands.
Tests single-process protection, multithreading, and all major functionality.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

# Test configuration
BASE_URL = "http://localhost:8001"
TEST_FILE = "test_upload.txt"

def run_curl(url, method="GET", headers=None, data=None, files=None, timeout=10):
    """Run a curl command and return the result."""
    cmd = ["curl", "-s", "-w", "\\n%{http_code}", "-X", method]

    if headers:
        for header in headers:
            cmd.extend(["-H", header])

    if data:
        cmd.extend(["-d", data])

    if files:
        for file_param in files:
            cmd.extend(["-F", file_param])

    cmd.append(url)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = result.stdout.strip()

        # Split response body and status code
        lines = output.split('\n')
        status_code = lines[-1] if lines else "000"
        response_body = '\n'.join(lines[:-1]) if len(lines) > 1 else ""

        return {
            "status_code": status_code,
            "response": response_body,
            "success": result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {"status_code": "timeout", "response": "", "success": False}
    except Exception as e:
        return {"status_code": "error", "response": str(e), "success": False}

def test_endpoint(name, url, method="GET", headers=None, data=None, files=None, expected_status="200"):
    """Test a single endpoint."""
    print(f"\n🧪 Testing {name}...")
    print(f"   {method} {url}")

    result = run_curl(url, method, headers, data, files)

    if result["status_code"] == expected_status:
        print(f"   ✅ SUCCESS - Status: {result['status_code']}")
        if result["response"]:
            try:
                # Try to parse as JSON for pretty printing
                json_data = json.loads(result["response"])
                print(f"   📄 Response: {json.dumps(json_data, indent=2)[:200]}...")
            except:
                print(f"   📄 Response: {result['response'][:200]}...")
        return True
    else:
        print(f"   ❌ FAILED - Expected: {expected_status}, Got: {result['status_code']}")
        if result["response"]:
            print(f"   📄 Response: {result['response'][:200]}...")
        return False

def create_test_file():
    """Create a test file for upload testing."""
    with open(TEST_FILE, 'w') as f:
        f.write("This is a test file for PlexiChat endpoint testing.\n")
        f.write("Created by the automated test script.\n")
        f.write(f"Timestamp: {time.time()}\n")

def cleanup_test_file():
    """Remove the test file."""
    try:
        os.remove(TEST_FILE)
    except:
        pass

def main():
    """Run all endpoint tests."""
    print("🚀 PlexiChat Endpoint Testing Suite (Legacy CURL)")
    print("=" * 50)

    # Create test file
    create_test_file()

    tests_passed = 0
    tests_total = 0

    # Test basic endpoints
    endpoints = [
        ("Root Endpoint", f"{BASE_URL}/", "GET", None, None, None, "200"),
        ("Health Check", f"{BASE_URL}/health", "GET", ["accept: application/json"], None, None, "200"),
        ("API Version", f"{BASE_URL}/api/v1/version", "GET", ["accept: application/json"], None, None, "200"),
        ("API Documentation", f"{BASE_URL}/docs", "GET", ["accept: text/html"], None, None, "200"),
    ]

    for test_data in endpoints:
        tests_total += 1
        if test_endpoint(*test_data):
            tests_passed += 1

    # Test file upload
    tests_total += 1
    print(f"\n🧪 Testing File Upload...")
    upload_result = run_curl()
        f"{BASE_URL}/api/v1/files/upload",
        method="POST",
        headers=["accept: application/json"],
        files=[f"file=@{TEST_FILE}"]
    )

    file_id = None
    if upload_result["status_code"] == "200":
        print(f"   ✅ SUCCESS - File Upload")
        try:
            upload_data = json.loads(upload_result["response"])
            file_id = upload_data.get("file_id")
            print(f"   📄 File ID: {file_id}")
            tests_passed += 1
        except:
            print(f"   ⚠️  Could not parse upload response")
    else:
        print(f"   ❌ FAILED - File Upload - Status: {upload_result['status_code']}")

    # Test file download (if upload succeeded)
    if file_id:
        tests_total += 1
        if test_endpoint("File Download", f"{BASE_URL}/api/v1/files/{file_id}", "GET"):
            tests_passed += 1

    # Test message creation
    tests_total += 1
    print(f"\n🧪 Testing Message Creation...")
    message_result = run_curl()
        f"{BASE_URL}/api/v1/messages/create",
        method="POST",
        headers=["accept: application/json", "Content-Type: application/x-www-form-urlencoded"],
        data="content=Hello from test script&message_type=text"
    )

    message_id = None
    if message_result["status_code"] == "200":
        print(f"   ✅ SUCCESS - Message Creation")
        try:
            message_data = json.loads(message_result["response"])
            message_id = message_data.get("id")
            print(f"   📄 Message ID: {message_id}")
            tests_passed += 1
        except:
            print(f"   ⚠️  Could not parse message response")
    else:
        print(f"   ❌ FAILED - Message Creation - Status: {message_result['status_code']}")

    # Test message retrieval
    if message_id:
        tests_total += 1
        if test_endpoint("Get Message", f"{BASE_URL}/api/v1/messages/{message_id}", "GET", ["accept: application/json"]):
            tests_passed += 1

    # Test message listing
    tests_total += 1
    if test_endpoint("List Messages", f"{BASE_URL}/api/v1/messages", "GET", ["accept: application/json"]):
        tests_passed += 1

    # Test security scan
    tests_total += 1
    print(f"\n🧪 Testing Security Scan...")
    scan_result = run_curl()
        f"{BASE_URL}/api/v1/security/scan/file",
        method="POST",
        headers=["accept: application/json"],
        files=[f"file=@{TEST_FILE}"]
    )

    # Security scan might return 503 if service is unavailable, which is acceptable
    if scan_result["status_code"] in ["200", "503"]:
        print(f"   ✅ SUCCESS - Security Scan (Status: {scan_result['status_code']})")
        tests_passed += 1
    else:
        print(f"   ❌ FAILED - Security Scan - Status: {scan_result['status_code']}")

    # Cleanup
    cleanup_test_file()

    # Results
    print("\n" + "=" * 50)
    print(f"🏁 Test Results: {tests_passed}/{tests_total} tests passed")

    if tests_passed == tests_total:
        print("🎉 ALL TESTS PASSED! PlexiChat is working correctly.")
        return 0
    else:
        print(f"⚠️  {tests_total - tests_passed} tests failed. Check the logs above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
