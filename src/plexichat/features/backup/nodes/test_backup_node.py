import asyncio
import base64
import hashlib
import sys
import time
from pathlib import Path

    import httpx
    from backup_node.backup_node_client import BackupNodeClient
    import argparse
    

#!/usr/bin/env python3
"""
PlexiChat Backup Node Test Suite
Tests the backup node functionality and API endpoints.
"""

# Add parent directory to path
sys.path.append(str(from pathlib import Path
Path(__file__).parent.parent))

try:
except ImportError as e:
    print(f" Missing dependencies: {e}")
    print("Install with: pip install httpx")
    sys.exit(1)


class BackupNodeTester:
    """Test suite for backup node functionality."""
    
    def __init__(self, node_address: str = "localhost", node_port: int = 8001):
        self.node_address = node_address
        self.node_port = node_port
        self.base_url = f"http://{node_address}:{node_port}"
        self.test_results = []
    
    def log_test(self, test_name: str, success: bool, message: str = ""):
        """Log test result."""
        status = " PASS" if success else " FAIL"
        print(f"{status} {test_name}: {message}")
        self.test_results.append({
            "test": test_name,
            "success": success,
            "message": message
        })
    
    async def test_health_check(self):
        """Test basic health check endpoint."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.base_url}/health", timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "healthy":
                        self.log_test("Health Check", True, "Node is healthy")
                        return True
                    else:
                        self.log_test("Health Check", False, f"Unexpected status: {data.get('status')}")
                        return False
                else:
                    self.log_test("Health Check", False, f"HTTP {response.status_code}")
                    return False
                    
        except Exception as e:
            self.log_test("Health Check", False, f"Connection failed: {e}")
            return False
    
    async def test_node_status(self):
        """Test node status endpoint."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.base_url}/api/v1/status", timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    required_fields = ["node_id", "node_type", "storage", "shards", "network"]
                    
                    for field in required_fields:
                        if field not in data:
                            self.log_test("Node Status", False, f"Missing field: {field}")
                            return False
                    
                    self.log_test("Node Status", True, f"Node ID: {data.get('node_id')}")
                    return True
                else:
                    self.log_test("Node Status", False, f"HTTP {response.status_code}")
                    return False
                    
        except Exception as e:
            self.log_test("Node Status", False, f"Request failed: {e}")
            return False
    
    async def test_shard_operations(self):
        """Test shard store, retrieve, and delete operations."""
        test_shard_id = f"test_shard_{int(time.time())}"
        test_data = b"Hello, backup node test!"
        test_hash = hashlib.sha256(test_data).hexdigest()
        
        try:
            async with httpx.AsyncClient() as client:
                # Test store shard
                store_data = {
                    "shard_id": test_shard_id,
                    "shard_data": base64.b64encode(test_data).decode(),
                    "original_hash": test_hash,
                    "source_node": "test_client",
                    "metadata": {"test": True}
                }
                
                response = await client.post(
                    f"{self.base_url}/api/v1/shards/store",
                    json=store_data,
                    timeout=10
                )
                
                if response.status_code != 200:
                    self.log_test("Shard Store", False, f"HTTP {response.status_code}")
                    return False
                
                result = response.json()
                if not result.get("success"):
                    self.log_test("Shard Store", False, "Store operation failed")
                    return False
                
                self.log_test("Shard Store", True, f"Stored shard: {test_shard_id}")
                
                # Test retrieve shard
                response = await client.get(f"{self.base_url}/api/v1/shards/{test_shard_id}")
                
                if response.status_code != 200:
                    self.log_test("Shard Retrieve", False, f"HTTP {response.status_code}")
                    return False
                
                result = response.json()
                retrieved_data = base64.b64decode(result["shard_data"])
                
                if retrieved_data != test_data:
                    self.log_test("Shard Retrieve", False, "Data mismatch")
                    return False
                
                self.log_test("Shard Retrieve", True, f"Retrieved {len(retrieved_data)} bytes")
                
                # Test delete shard
                response = await client.delete(f"{self.base_url}/api/v1/shards/{test_shard_id}")
                
                if response.status_code != 200:
                    self.log_test("Shard Delete", False, f"HTTP {response.status_code}")
                    return False
                
                result = response.json()
                if not result.get("success"):
                    self.log_test("Shard Delete", False, "Delete operation failed")
                    return False
                
                self.log_test("Shard Delete", True, f"Deleted shard: {test_shard_id}")
                
                # Verify shard is gone
                response = await client.get(f"{self.base_url}/api/v1/shards/{test_shard_id}")
                if response.status_code != 404:
                    self.log_test("Shard Cleanup Verification", False, "Shard still exists after deletion")
                    return False
                
                self.log_test("Shard Cleanup Verification", True, "Shard properly deleted")
                return True
                
        except Exception as e:
            self.log_test("Shard Operations", False, f"Exception: {e}")
            return False
    
    async def test_list_shards(self):
        """Test listing shards."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.base_url}/api/v1/shards", timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    data.get("shards", [])
                    total_count = data.get("total_count", 0)
                    
                    self.log_test("List Shards", True, f"Found {total_count} shards")
                    return True
                else:
                    self.log_test("List Shards", False, f"HTTP {response.status_code}")
                    return False
                    
        except Exception as e:
            self.log_test("List Shards", False, f"Request failed: {e}")
            return False
    
    async def test_client_library(self):
        """Test the Python client library."""
        try:
            async with BackupNodeClient(self.node_address, self.node_port) as client:
                # Test health check
                health = await client.health_check()
                if not health.get("status") == "healthy":
                    self.log_test("Client Health Check", False, "Health check failed")
                    return False
                
                # Test shard operations
                test_data = b"Client library test data"
                test_shard_id = f"client_test_{int(time.time())}"
                
                # Store
                success = await client.store_shard(test_shard_id, test_data, "test_client")
                if not success:
                    self.log_test("Client Store", False, "Store operation failed")
                    return False
                
                # Retrieve
                retrieved_data = await client.retrieve_shard(test_shard_id)
                if retrieved_data != test_data:
                    self.log_test("Client Retrieve", False, "Data mismatch")
                    return False
                
                # Delete
                success = await client.delete_shard(test_shard_id)
                if not success:
                    self.log_test("Client Delete", False, "Delete operation failed")
                    return False
                
                self.log_test("Client Library", True, "All client operations successful")
                return True
                
        except Exception as e:
            self.log_test("Client Library", False, f"Exception: {e}")
            return False
    
    async def test_node_registration(self):
        """Test node registration."""
        try:
            async with httpx.AsyncClient() as client:
                registration_data = {
                    "node_id": "test_node_123",
                    "node_type": "test",
                    "address": "127.0.0.1",
                    "port": 9999,
                    "storage_capacity": 1000000
                }
                
                response = await client.post(
                    f"{self.base_url}/api/v1/nodes/register",
                    json=registration_data,
                    timeout=5
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get("success"):
                        self.log_test("Node Registration", True, "Node registered successfully")
                        return True
                    else:
                        self.log_test("Node Registration", False, "Registration failed")
                        return False
                else:
                    self.log_test("Node Registration", False, f"HTTP {response.status_code}")
                    return False
                    
        except Exception as e:
            self.log_test("Node Registration", False, f"Request failed: {e}")
            return False
    
    async def run_all_tests(self):
        """Run all tests."""
        print(" PlexiChat Backup Node Test Suite")
        print("=" * 50)
        
        tests = [
            self.test_health_check,
            self.test_node_status,
            self.test_list_shards,
            self.test_shard_operations,
            self.test_node_registration,
            self.test_client_library
        ]
        
        passed = 0
        total = len(tests)
        
        for test in tests:
            try:
                result = await test()
                if result:
                    passed += 1
            except Exception as e:
                print(f" Test failed with exception: {e}")
        
        print("\n" + "=" * 50)
        print(f" Test Results: {passed}/{total} passed")
        
        if passed == total:
            print(" All tests passed!")
            return True
        else:
            print(f" {total - passed} tests failed")
            return False
    
    def print_summary(self):
        """Print test summary."""
        print("\n Detailed Test Results:")
        print("-" * 30)
        
        for result in self.test_results:
            status = "" if result["success"] else ""
            print(f"{status} {result['test']}: {result['message']}")


async def main():
    """Main test function."""
    parser = argparse.ArgumentParser(description="PlexiChat Backup Node Test Suite")
    parser.add_argument("--address", default="localhost", help="Backup node address")
    parser.add_argument("--port", type=int, default=8001, help="Backup node port")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    tester = BackupNodeTester(args.address, args.port)
    
    print(f" Testing backup node at {args.address}:{args.port}")
    print(" Starting tests...\n")
    
    success = await tester.run_all_tests()
    
    if args.verbose:
        tester.print_summary()
    
    if success:
        print("\n All tests completed successfully!")
        sys.exit(0)
    else:
        print("\n Some tests failed!")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
