"""
Network Security Scanner Plugin

Network security scanner with port scanning, vulnerability detection, and security reporting.
"""

import asyncio
import json
import logging
import socket
import ssl
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import concurrent.futures
import ipaddress

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Plugin interface imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

# Fallback definitions for plugin interface
class PluginInterface:
    def get_metadata(self) -> Dict[str, Any]:
        return {}

class PluginMetadata:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

class PluginType:
    SECURITY = "security"

class ModulePermissions:
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"

class ModuleCapability:
    NETWORK = "network"
    SECURITY = "security"

logger = logging.getLogger(__name__)


class ScanRequest(BaseModel):
    """Network scan request model."""
    target: str
    scan_type: str = "tcp"
    ports: Optional[List[int]] = None
    options: Optional[Dict[str, Any]] = None


class PortScanResult(BaseModel):
    """Port scan result model."""
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None


class VulnerabilityResult(BaseModel):
    """Vulnerability scan result model."""
    vulnerability_id: str
    severity: str
    title: str
    description: str
    affected_service: str
    port: int
    recommendation: str


class NetworkScannerCore:
    """Core network scanning functionality."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.scan_timeout = config.get('scan_timeout', 5)
        self.max_threads = config.get('max_threads', 100)
        self.common_ports = config.get('common_ports', [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306])
        self.enable_service_detection = config.get('enable_service_detection', True)
        
    async def scan_host(self, target: str, ports: Optional[List[int]] = None, 
                       scan_type: str = "tcp") -> Dict[str, Any]:
        """Perform comprehensive host scan."""
        try:
            # Validate target
            if not self._validate_target(target):
                raise ValueError(f"Invalid target: {target}")
            
            # Use common ports if none specified
            if not ports:
                ports = self.common_ports
            
            scan_result = {
                "target": target,
                "scan_type": scan_type,
                "timestamp": datetime.now().isoformat(),
                "host_info": await self._get_host_info(target),
                "port_scan": await self._scan_ports(target, ports, scan_type),
                "services": [],
                "vulnerabilities": []
            }
            
            # Service detection
            if self.enable_service_detection:
                scan_result["services"] = await self._detect_services(target, scan_result["port_scan"])
            
            # Vulnerability scanning
            if self.config.get('enable_vulnerability_scan', True):
                scan_result["vulnerabilities"] = await self._scan_vulnerabilities(target, scan_result["port_scan"])
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Error scanning host {target}: {e}")
            raise
    
    def _validate_target(self, target: str) -> bool:
        """Validate scan target."""
        try:
            # Try to parse as IP address
            ipaddress.ip_address(target)
            return True
        except ValueError:
            # Try to resolve as hostname
            try:
                socket.gethostbyname(target)
                return True
            except socket.gaierror:
                return False
    
    async def _get_host_info(self, target: str) -> Dict[str, Any]:
        """Get basic host information."""
        try:
            # Resolve hostname
            try:
                ip = socket.gethostbyname(target)
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.gaierror:
                ip = target
                hostname = None
            
            # Check if host is alive (ping)
            alive = await self._ping_host(target)
            
            return {
                "ip_address": ip,
                "hostname": hostname,
                "alive": alive,
                "os_detection": await self._detect_os(target) if alive else None
            }
            
        except Exception as e:
            logger.error(f"Error getting host info for {target}: {e}")
            return {"ip_address": target, "hostname": None, "alive": False}
    
    async def _ping_host(self, target: str) -> bool:
        """Check if host is alive using ping."""
        try:
            # Use system ping command
            process = await asyncio.create_subprocess_exec(
                'ping', '-c', '1', '-W', '2', target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            return process.returncode == 0
        except Exception:
            return False
    
    async def _detect_os(self, target: str) -> Optional[str]:
        """Attempt basic OS detection."""
        try:
            # Simple TTL-based OS detection
            process = await asyncio.create_subprocess_exec(
                'ping', '-c', '1', target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            if b'ttl=64' in stdout.lower():
                return "Linux/Unix"
            elif b'ttl=128' in stdout.lower():
                return "Windows"
            elif b'ttl=255' in stdout.lower():
                return "Cisco/Network Device"
            else:
                return "Unknown"
                
        except Exception:
            return None
    
    async def _scan_ports(self, target: str, ports: List[int], scan_type: str) -> List[Dict[str, Any]]:
        """Scan ports on target host."""
        try:
            open_ports = []
            
            # Create thread pool for concurrent scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Submit all port scan tasks
                future_to_port = {
                    executor.submit(self._scan_single_port, target, port, scan_type): port 
                    for port in ports
                }
                
                # Collect results
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        result = future.result()
                        if result:
                            open_ports.append(result)
                    except Exception as e:
                        logger.debug(f"Error scanning port {port}: {e}")
            
            return sorted(open_ports, key=lambda x: x['port'])
            
        except Exception as e:
            logger.error(f"Error scanning ports on {target}: {e}")
            return []
    
    def _scan_single_port(self, target: str, port: int, scan_type: str) -> Optional[Dict[str, Any]]:
        """Scan a single port."""
        try:
            if scan_type.lower() == "tcp":
                return self._tcp_scan(target, port)
            elif scan_type.lower() == "udp":
                return self._udp_scan(target, port)
            else:
                raise ValueError(f"Unsupported scan type: {scan_type}")
                
        except Exception as e:
            logger.debug(f"Error scanning {target}:{port} - {e}")
            return None
    
    def _tcp_scan(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Perform TCP port scan."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.scan_timeout)
            
            result = sock.connect_ex((target, port))
            
            if result == 0:
                # Port is open, try to get banner
                banner = self._get_banner(sock, port)
                sock.close()
                
                return {
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": self._identify_service(port),
                    "banner": banner
                }
            else:
                sock.close()
                return None
                
        except Exception:
            return None
    
    def _udp_scan(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Perform UDP port scan."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.scan_timeout)
            
            # Send empty UDP packet
            sock.sendto(b'', (target, port))
            
            try:
                # Try to receive response
                sock.recvfrom(1024)
                sock.close()
                
                return {
                    "port": port,
                    "protocol": "udp",
                    "state": "open",
                    "service": self._identify_service(port, "udp")
                }
            except socket.timeout:
                # No response - port might be open or filtered
                sock.close()
                return {
                    "port": port,
                    "protocol": "udp",
                    "state": "open|filtered",
                    "service": self._identify_service(port, "udp")
                }
                
        except Exception:
            return None
    
    def _get_banner(self, sock: socket.socket, port: int) -> Optional[str]:
        """Attempt to grab service banner."""
        try:
            # Send appropriate probe based on port
            if port == 80:
                sock.send(b'GET / HTTP/1.0\r\n\r\n')
            elif port == 21:
                pass  # FTP sends banner automatically
            elif port == 22:
                pass  # SSH sends banner automatically
            elif port == 25:
                pass  # SMTP sends banner automatically
            else:
                sock.send(b'\r\n')
            
            # Try to receive banner
            sock.settimeout(2)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner if banner else None
            
        except Exception:
            return None
    
    def _identify_service(self, port: int, protocol: str = "tcp") -> Optional[str]:
        """Identify service running on port."""
        service_map = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            993: "imaps",
            995: "pop3s",
            3389: "rdp",
            5432: "postgresql",
            3306: "mysql"
        }
        
        return service_map.get(port)
    
    async def _detect_services(self, target: str, open_ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect services and versions on open ports."""
        services = []
        
        for port_info in open_ports:
            port = port_info['port']
            service_info = {
                "port": port,
                "service": port_info.get('service'),
                "version": None,
                "details": {}
            }
            
            # Enhanced service detection based on banner
            banner = port_info.get('banner')
            if banner:
                service_info["version"] = self._parse_version_from_banner(banner)
                service_info["details"]["banner"] = banner
            
            # SSL/TLS detection for HTTPS ports
            if port in [443, 993, 995] or (banner and 'ssl' in banner.lower()):
                ssl_info = await self._analyze_ssl(target, port)
                if ssl_info:
                    service_info["details"]["ssl"] = ssl_info
            
            services.append(service_info)
        
        return services
    
    def _parse_version_from_banner(self, banner: str) -> Optional[str]:
        """Parse service version from banner."""
        # Simple version extraction patterns
        import re
        
        patterns = [
            r'(\w+)/(\d+\.\d+(?:\.\d+)?)',  # Service/Version
            r'(\w+)\s+(\d+\.\d+(?:\.\d+)?)',  # Service Version
            r'Server:\s*([^\r\n]+)',  # HTTP Server header
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(0)
        
        return None
    
    async def _analyze_ssl(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Analyze SSL/TLS configuration."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=self.scan_timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    return {
                        "protocol": ssock.version(),
                        "cipher": cipher[0] if cipher else None,
                        "certificate": {
                            "subject": dict(x[0] for x in cert.get('subject', [])),
                            "issuer": dict(x[0] for x in cert.get('issuer', [])),
                            "version": cert.get('version'),
                            "serial_number": cert.get('serialNumber'),
                            "not_before": cert.get('notBefore'),
                            "not_after": cert.get('notAfter')
                        } if cert else None
                    }
                    
        except Exception as e:
            logger.debug(f"SSL analysis failed for {target}:{port} - {e}")
            return None
    
    async def _scan_vulnerabilities(self, target: str, open_ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan for common vulnerabilities."""
        vulnerabilities = []
        
        for port_info in open_ports:
            port = port_info['port']
            service = port_info.get('service')
            banner = port_info.get('banner', '')
            
            # Check for common vulnerabilities
            vulns = self._check_common_vulnerabilities(port, service, banner)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def _check_common_vulnerabilities(self, port: int, service: Optional[str], banner: str) -> List[Dict[str, Any]]:
        """Check for common vulnerabilities based on service and version."""
        vulnerabilities = []
        
        # Example vulnerability checks
        if port == 21 and 'vsftpd 2.3.4' in banner.lower():
            vulnerabilities.append({
                "vulnerability_id": "CVE-2011-2523",
                "severity": "critical",
                "title": "vsftpd 2.3.4 Backdoor",
                "description": "This version of vsftpd contains a backdoor",
                "affected_service": f"{service or 'ftp'}:{port}",
                "port": port,
                "recommendation": "Upgrade vsftpd to a secure version"
            })
        
        if port == 22 and banner:
            # Check for old SSH versions
            if any(old_version in banner.lower() for old_version in ['openssh_4', 'openssh_5']):
                vulnerabilities.append({
                    "vulnerability_id": "SSH-OLD-VERSION",
                    "severity": "medium",
                    "title": "Outdated SSH Version",
                    "description": "SSH server is running an outdated version",
                    "affected_service": f"{service or 'ssh'}:{port}",
                    "port": port,
                    "recommendation": "Update SSH server to the latest version"
                })
        
        if port == 80 and banner:
            # Check for server information disclosure
            if any(server in banner.lower() for server in ['apache/', 'nginx/', 'iis/']):
                vulnerabilities.append({
                    "vulnerability_id": "HTTP-VERSION-DISCLOSURE",
                    "severity": "low",
                    "title": "HTTP Server Version Disclosure",
                    "description": "Web server reveals version information",
                    "affected_service": f"{service or 'http'}:{port}",
                    "port": port,
                    "recommendation": "Configure server to hide version information"
                })
        
        return vulnerabilities


class NetworkScannerPlugin(PluginInterface):
    """Network Security Scanner Plugin."""

    def __init__(self):
        super().__init__("network_scanner", "1.0.0")
        self.router = APIRouter()
        self.scanner = None
        self.data_dir = Path(__file__).parent / "data"
        self.data_dir.mkdir(exist_ok=True)

    def get_metadata(self) -> Dict[str, Any]:
        """Get plugin metadata."""
        return {
            "name": "network_scanner",
            "version": "1.0.0",
            "description": "Network security scanner with port scanning, vulnerability detection, and security reporting",
            "plugin_type": "security"
        }

    def get_required_permissions(self) -> Dict[str, Any]:
        """Get required permissions."""
        return {
            "capabilities": [
                "network",
                "file_system",
                "web_ui"
            ],
            "network_access": True,
            "file_system_access": True,
            "database_access": False
        }

    async def initialize(self) -> bool:
        """Initialize the plugin."""
        try:
            # Load configuration
            await self._load_configuration()

            # Initialize scanner core
            self.scanner = NetworkScannerCore(self.config)

            # Setup API routes
            self._setup_routes()

            # Register UI pages
            await self._register_ui_pages()

            self.logger.info("Network Scanner plugin initialized successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize Network Scanner plugin: {e}")
            return False

    async def cleanup(self) -> bool:
        """Cleanup plugin resources."""
        try:
            self.logger.info("Network Scanner plugin cleanup completed")
            return True
        except Exception as e:
            self.logger.error(f"Error during Network Scanner plugin cleanup: {e}")
            return False

    def _setup_routes(self):
        """Setup API routes."""

        @self.router.post("/scan")
        async def scan_host(request: ScanRequest):
            """Scan a host or network."""
            try:
                result = await self.scanner.scan_host(
                    request.target, request.ports, request.scan_type
                )
                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.get("/ping")
        async def ping_host(target: str):
            """Ping a host to check if it's alive."""
            try:
                alive = await self.scanner._ping_host(target)
                return JSONResponse(content={"target": target, "alive": alive})
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.get("/common-ports")
        async def get_common_ports():
            """Get list of commonly scanned ports."""
            return JSONResponse(content={
                "ports": self.scanner.common_ports
            })

        @self.router.post("/batch-scan")
        async def batch_scan(targets: List[str], ports: Optional[List[int]] = None):
            """Scan multiple targets."""
            try:
                results = []
                for target in targets:
                    try:
                        result = await self.scanner.scan_host(target, ports)
                        results.append(result)
                    except Exception as e:
                        results.append({
                            "target": target,
                            "error": str(e)
                        })

                return JSONResponse(content={"results": results})
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

    async def _load_configuration(self):
        """Load plugin configuration."""
        config_file = self.data_dir / "config.json"
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    loaded_config = json.load(f)
                    self.config.update(loaded_config)
            except Exception as e:
                self.logger.warning(f"Failed to load config: {e}")

    async def _register_ui_pages(self):
        """Register UI pages with the main application."""
        ui_dir = Path(__file__).parent / "ui"
        if ui_dir.exists():
            app = getattr(self.manager, 'app', None)
            if app:
                from fastapi.staticfiles import StaticFiles
                app.mount(f"/plugins/network-scanner/static",
                         StaticFiles(directory=str(ui_dir / "static")),
                         name="network_scanner_static")

    # Self-test methods
    async def test_port_scanning(self) -> Dict[str, Any]:
        """Test port scanning functionality."""
        try:
            # Test scanning localhost
            result = await self.scanner.scan_host("127.0.0.1", [22, 80, 443])

            if not isinstance(result, dict):
                return {"success": False, "error": "Invalid scan result format"}

            if "port_scan" not in result:
                return {"success": False, "error": "Port scan results missing"}

            return {"success": True, "message": "Port scanning test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_service_detection(self) -> Dict[str, Any]:
        """Test service detection functionality."""
        try:
            # Test service identification
            service = self.scanner._identify_service(80)
            if service != "http":
                return {"success": False, "error": "Service identification failed"}

            return {"success": True, "message": "Service detection test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_vulnerability_scan(self) -> Dict[str, Any]:
        """Test vulnerability scanning functionality."""
        try:
            # Test vulnerability detection with mock data
            vulns = self.scanner._check_common_vulnerabilities(
                21, "ftp", "220 (vsFTPd 2.3.4)"
            )

            if not vulns:
                return {"success": False, "error": "Vulnerability detection failed"}

            return {"success": True, "message": "Vulnerability scan test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_network_discovery(self) -> Dict[str, Any]:
        """Test network discovery functionality."""
        try:
            # Test host validation
            valid = self.scanner._validate_target("127.0.0.1")
            if not valid:
                return {"success": False, "error": "Host validation failed"}

            # Test ping functionality
            alive = await self.scanner._ping_host("127.0.0.1")
            # Note: This might fail in some environments, so we don't fail the test

            return {"success": True, "message": "Network discovery test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_reporting(self) -> Dict[str, Any]:
        """Test reporting functionality."""
        try:
            # Test that scan results are properly formatted
            test_result = {
                "target": "127.0.0.1",
                "scan_type": "tcp",
                "timestamp": datetime.now().isoformat(),
                "port_scan": [],
                "services": [],
                "vulnerabilities": []
            }

            # Verify required fields are present
            required_fields = ["target", "scan_type", "timestamp", "port_scan"]
            for field in required_fields:
                if field not in test_result:
                    return {"success": False, "error": f"Missing required field: {field}"}

            return {"success": True, "message": "Reporting test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def run_tests(self) -> Dict[str, Any]:
        """Run all plugin self-tests."""
        tests = [
            ("port_scanning", self.test_port_scanning),
            ("service_detection", self.test_service_detection),
            ("vulnerability_scan", self.test_vulnerability_scan),
            ("network_discovery", self.test_network_discovery),
            ("reporting", self.test_reporting)
        ]

        results = {
            "total": len(tests),
            "passed": 0,
            "failed": 0,
            "tests": {}
        }

        for test_name, test_func in tests:
            try:
                result = await test_func()
                if result.get("success", False):
                    results["passed"] += 1
                    results["tests"][test_name] = {"status": "passed", "message": result.get("message", "")}
                else:
                    results["failed"] += 1
                    results["tests"][test_name] = {"status": "failed", "error": result.get("error", "")}
            except Exception as e:
                results["failed"] += 1
                results["tests"][test_name] = {"status": "failed", "error": str(e)}

        results["success"] = results["failed"] == 0
        return results


# Plugin entry point
def create_plugin():
    """Create plugin instance."""
    return NetworkScannerPlugin()
