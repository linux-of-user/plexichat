"""
SSL/TLS functionality tests for PlexiChat.
Tests certificate generation, validation, and secure connections.
"""

import ssl
import socket
import tempfile
from pathlib import Path
from typing import Dict, Any
import logging
from datetime import datetime
import subprocess

from .test_base import BaseTest, TestResult

logger = logging.getLogger(__name__)


class SSLTest(BaseTest):
    """Test SSL/TLS functionality."""
    
    def __init__(self):
        super().__init__()
        self.temp_dir = None
        self.cert_file = None
        self.key_file = None
    
    async def setup(self):
        """Setup test environment with temporary certificates."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.cert_file = self.temp_dir / "test_cert.pem"
        self.key_file = self.temp_dir / "test_key.pem"
    
    async def teardown(self):
        """Cleanup temporary files."""
        if self.temp_dir and self.temp_dir.exists():
            import shutil
            shutil.rmtree(self.temp_dir)
    
    async def test_certificate_generation(self):
        """Test SSL certificate generation."""
        start_time = datetime.now()
        
        try:
            # Generate self-signed certificate using openssl
            cmd = [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(self.key_file),
                "-out", str(self.cert_file),
                "-days", "365", "-nodes",
                "-subj", "/C=US/ST=Test/L=Test/O=PlexiChat/CN=localhost"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Check if files were created
            cert_exists = self.cert_file.exists()
            key_exists = self.key_file.exists()
            
            duration = (datetime.now() - start_time).total_seconds() * 1000
            
            if cert_exists and key_exists:
                self.add_result(TestResult(
                    test_name="Certificate Generation",
                    category="SSL",
                    endpoint="/ssl/generate_cert",
                    method="GENERATE",
                    status="passed",
                    duration_ms=duration,
                    request_data={"cert_type": "self-signed", "key_size": 2048},
                    response_data={"cert_created": True, "key_created": True}
                ))
            else:
                self.add_result(TestResult(
                    test_name="Certificate Generation",
                    category="SSL",
                    endpoint="/ssl/generate_cert",
                    method="GENERATE",
                    status="failed",
                    duration_ms=duration,
                    error_message=f"Certificate generation failed: {result.stderr}"
                ))
                
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds() * 1000
            self.add_result(TestResult(
                test_name="Certificate Generation",
                category="SSL",
                endpoint="/ssl/generate_cert",
                method="GENERATE",
                status="failed",
                duration_ms=duration,
                error_message=str(e)
            ))
    
    async def test_certificate_validation(self):
        """Test SSL certificate validation."""
        start_time = datetime.now()
        
        try:
            if not self.cert_file.exists():
                await self.test_certificate_generation()
            
            # Load and validate certificate
            with open(self.cert_file, 'rb') as f:
                cert_data = f.read()
            
            # Parse certificate
            cert = ssl.PEM_cert_to_DER_cert(cert_data.decode())
            
            # Basic validation - check if it's a valid certificate
            is_valid = len(cert) > 0
            
            duration = (datetime.now() - start_time).total_seconds() * 1000
            
            self.add_result(TestResult(
                test_name="Certificate Validation",
                category="SSL",
                endpoint="/ssl/validate_cert",
                method="VALIDATE",
                status="passed" if is_valid else "failed",
                duration_ms=duration,
                request_data={"cert_file": str(self.cert_file)},
                response_data={"valid": is_valid, "cert_size": len(cert)}
            ))
            
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds() * 1000
            self.add_result(TestResult(
                test_name="Certificate Validation",
                category="SSL",
                endpoint="/ssl/validate_cert",
                method="VALIDATE",
                status="failed",
                duration_ms=duration,
                error_message=str(e)
            ))
    
    async def test_ssl_context_creation(self):
        """Test SSL context creation."""
        start_time = datetime.now()
        
        try:
            if not self.cert_file.exists() or not self.key_file.exists():
                await self.test_certificate_generation()
            
            # Create SSL context
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(str(self.cert_file), str(self.key_file))
            
            # Verify context was created successfully
            context_created = context is not None
            
            duration = (datetime.now() - start_time).total_seconds() * 1000
            
            self.add_result(TestResult(
                test_name="SSL Context Creation",
                category="SSL",
                endpoint="/ssl/create_context",
                method="CREATE",
                status="passed" if context_created else "failed",
                duration_ms=duration,
                request_data={"cert_file": str(self.cert_file), "key_file": str(self.key_file)},
                response_data={"context_created": context_created, "protocol": str(context.protocol)}
            ))
            
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds() * 1000
            self.add_result(TestResult(
                test_name="SSL Context Creation",
                category="SSL",
                endpoint="/ssl/create_context",
                method="CREATE",
                status="failed",
                duration_ms=duration,
                error_message=str(e)
            ))
    
    async def test_ssl_socket_creation(self):
        """Test SSL socket creation."""
        start_time = datetime.now()
        
        try:
            if not self.cert_file.exists() or not self.key_file.exists():
                await self.test_certificate_generation()
            
            # Create SSL context
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(str(self.cert_file), str(self.key_file))
            
            # Create SSL socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssl_sock = context.wrap_socket(sock, server_side=True)
            
            socket_created = ssl_sock is not None
            
            # Clean up
            ssl_sock.close()
            
            duration = (datetime.now() - start_time).total_seconds() * 1000
            
            self.add_result(TestResult(
                test_name="SSL Socket Creation",
                category="SSL",
                endpoint="/ssl/create_socket",
                method="CREATE",
                status="passed" if socket_created else "failed",
                duration_ms=duration,
                request_data={"socket_type": "server_side"},
                response_data={"socket_created": socket_created}
            ))
            
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds() * 1000
            self.add_result(TestResult(
                test_name="SSL Socket Creation",
                category="SSL",
                endpoint="/ssl/create_socket",
                method="CREATE",
                status="failed",
                duration_ms=duration,
                error_message=str(e)
            ))
    
    async def run_all_tests(self):
        """Run all SSL tests."""
        await self.setup()
        try:
            await self.test_certificate_generation()
            await self.test_certificate_validation()
            await self.test_ssl_context_creation()
            await self.test_ssl_socket_creation()
        finally:
            await self.teardown()
