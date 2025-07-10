"""
Enhanced Certificate Management System
Handles automatic certificate generation, renewal, and management with Let's Encrypt integration.
Includes automatic listen address configuration and domain management.
"""

import asyncio
import ssl
import os
import json
import subprocess
import time
import socket
import ipaddress
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import logging

logger = logging.getLogger(__name__)

@dataclass
class CertificateInfo:
    """Certificate information structure."""
    domain: str
    cert_path: str
    key_path: str
    fullchain_path: str
    issued_date: datetime
    expiry_date: datetime
    issuer: str
    is_self_signed: bool
    auto_renew: bool
    last_renewal_attempt: Optional[datetime] = None
    renewal_failures: int = 0

@dataclass
class DomainConfig:
    """Domain configuration for certificate management."""
    domain: str
    use_letsencrypt: bool = True
    email: str = ""
    webroot_path: str = "./web"
    challenge_type: str = "http-01"  # http-01, dns-01, tls-alpn-01
    auto_renew: bool = True
    renewal_days_before: int = 30
    backup_cert: bool = True
    listen_addresses: List[str] = None  # Auto-configured if None
    ports: List[int] = None  # [80, 443] if None


@dataclass
class NetworkConfig:
    """Network configuration for automatic address detection."""
    auto_detect_ip: bool = True
    preferred_interfaces: List[str] = None  # ['eth0', 'wlan0'] etc.
    exclude_loopback: bool = True
    exclude_private: bool = False
    ipv6_enabled: bool = True
    custom_addresses: List[str] = None


class NetworkAddressManager:
    """Manages network address detection and configuration."""

    def __init__(self, config: NetworkConfig = None):
        self.config = config or NetworkConfig()

    def get_local_addresses(self) -> List[str]:
        """Get all local IP addresses."""
        addresses = []

        try:
            import netifaces

            # Get all network interfaces
            interfaces = netifaces.interfaces()

            for interface in interfaces:
                # Skip loopback if configured
                if self.config.exclude_loopback and interface.startswith('lo'):
                    continue

                # Check preferred interfaces
                if (self.config.preferred_interfaces and
                    interface not in self.config.preferred_interfaces):
                    continue

                # Get addresses for interface
                addrs = netifaces.ifaddresses(interface)

                # IPv4 addresses
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        addr = addr_info.get('addr')
                        if addr and self._is_valid_address(addr, ipv4=True):
                            addresses.append(addr)

                # IPv6 addresses
                if self.config.ipv6_enabled and netifaces.AF_INET6 in addrs:
                    for addr_info in addrs[netifaces.AF_INET6]:
                        addr = addr_info.get('addr')
                        if addr and self._is_valid_address(addr, ipv4=False):
                            # Remove zone identifier if present
                            addr = addr.split('%')[0]
                            addresses.append(f"[{addr}]")

        except ImportError:
            # Fallback method without netifaces
            addresses = self._get_addresses_fallback()

        # Add custom addresses
        if self.config.custom_addresses:
            addresses.extend(self.config.custom_addresses)

        return list(set(addresses))  # Remove duplicates

    def _is_valid_address(self, addr: str, ipv4: bool = True) -> bool:
        """Check if address is valid for our use."""
        try:
            ip = ipaddress.ip_address(addr)

            # Skip loopback
            if self.config.exclude_loopback and ip.is_loopback:
                return False

            # Skip private addresses if configured
            if self.config.exclude_private and ip.is_private:
                return False

            return True

        except ValueError:
            return False

    def _get_addresses_fallback(self) -> List[str]:
        """Fallback method to get addresses without netifaces."""
        addresses = []

        try:
            # Get hostname and resolve to IP
            hostname = socket.gethostname()
            host_ip = socket.gethostbyname(hostname)
            if self._is_valid_address(host_ip):
                addresses.append(host_ip)

            # Try to connect to external service to get local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                if self._is_valid_address(local_ip):
                    addresses.append(local_ip)

        except Exception as e:
            logger.warning(f"Fallback address detection failed: {e}")

        return addresses

    def get_public_ip(self) -> Optional[str]:
        """Get public IP address."""
        try:
            import requests
            response = requests.get('https://api.ipify.org', timeout=5)
            if response.status_code == 200:
                return response.text.strip()
        except:
            pass

        # Fallback methods
        try:
            import urllib.request
            with urllib.request.urlopen('https://api.ipify.org', timeout=5) as response:
                return response.read().decode().strip()
        except:
            pass

        return None


class CertificateManager:
    """Advanced certificate management with Let's Encrypt integration."""
    
    def __init__(self, config_path: str = "certificates.json", network_config: NetworkConfig = None):
        self.config_path = Path(config_path)
        self.certs_dir = Path("certs")
        self.certs_dir.mkdir(exist_ok=True)

        # Certificate storage
        self.certificates: Dict[str, CertificateInfo] = {}
        self.domain_configs: Dict[str, DomainConfig] = {}

        # Network address manager
        self.network_manager = NetworkAddressManager(network_config)

        # Let's Encrypt settings
        self.acme_server = "https://acme-v02.api.letsencrypt.org/directory"
        self.acme_staging = "https://acme-staging-v02.api.letsencrypt.org/directory"
        self.use_staging = False

        # Load existing configuration
        self.load_config()

        # Start renewal monitoring
        self._renewal_task = None
        
    def load_config(self):
        """Load certificate configuration from file."""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    data = json.load(f)
                
                # Load certificates
                for cert_data in data.get('certificates', []):
                    cert_info = CertificateInfo(**cert_data)
                    self.certificates[cert_info.domain] = cert_info
                
                # Load domain configs
                for domain_data in data.get('domains', []):
                    domain_config = DomainConfig(**domain_data)
                    self.domain_configs[domain_config.domain] = domain_config
                    
                logger.info(f"Loaded {len(self.certificates)} certificates and {len(self.domain_configs)} domain configs")
                
            except Exception as e:
                logger.error(f"Failed to load certificate config: {e}")
    
    def save_config(self):
        """Save certificate configuration to file."""
        try:
            data = {
                'certificates': [asdict(cert) for cert in self.certificates.values()],
                'domains': [asdict(domain) for domain in self.domain_configs.values()],
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.config_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
                
        except Exception as e:
            logger.error(f"Failed to save certificate config: {e}")
    
    async def add_domain(self, domain: str, email: str = "", use_letsencrypt: bool = True, 
                        auto_renew: bool = True) -> bool:
        """Add a domain for certificate management."""
        try:
            domain_config = DomainConfig(
                domain=domain,
                use_letsencrypt=use_letsencrypt,
                email=email,
                auto_renew=auto_renew
            )
            
            self.domain_configs[domain] = domain_config
            self.save_config()
            
            # Generate initial certificate
            success = await self.generate_certificate(domain)
            if success:
                logger.info(f"Successfully added domain: {domain}")
                return True
            else:
                logger.error(f"Failed to generate initial certificate for: {domain}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to add domain {domain}: {e}")
            return False
    
    async def generate_certificate(self, domain: str) -> bool:
        """Generate certificate for a domain."""
        domain_config = self.domain_configs.get(domain)
        if not domain_config:
            logger.error(f"No configuration found for domain: {domain}")
            return False
        
        try:
            if domain_config.use_letsencrypt:
                return await self._generate_letsencrypt_cert(domain, domain_config)
            else:
                return await self._generate_self_signed_cert(domain, domain_config)
                
        except Exception as e:
            logger.error(f"Failed to generate certificate for {domain}: {e}")
            return False
    
    async def _generate_letsencrypt_cert(self, domain: str, config: DomainConfig) -> bool:
        """Generate Let's Encrypt certificate using certbot."""
        try:
            # Ensure certbot is available
            if not self._check_certbot():
                logger.error("Certbot not available, falling back to self-signed")
                return await self._generate_self_signed_cert(domain, config)
            
            # Prepare certbot command
            server_url = self.acme_staging if self.use_staging else self.acme_server
            
            cmd = [
                "certbot", "certonly",
                "--webroot",
                "--webroot-path", config.webroot_path,
                "--email", config.email,
                "--agree-tos",
                "--no-eff-email",
                "--server", server_url,
                "--cert-name", domain,
                "-d", domain
            ]
            
            if self.use_staging:
                cmd.append("--test-cert")
            
            # Run certbot
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                # Certificate generated successfully
                cert_info = self._create_cert_info_letsencrypt(domain)
                if cert_info:
                    self.certificates[domain] = cert_info
                    self.save_config()
                    logger.info(f"Let's Encrypt certificate generated for: {domain}")
                    return True
            else:
                logger.error(f"Certbot failed for {domain}: {stderr.decode()}")
                # Fallback to self-signed
                return await self._generate_self_signed_cert(domain, config)
                
        except Exception as e:
            logger.error(f"Let's Encrypt generation failed for {domain}: {e}")
            return await self._generate_self_signed_cert(domain, config)
        
        return False

    async def _generate_self_signed_cert(self, domain: str, config: DomainConfig) -> bool:
        """Generate self-signed certificate."""
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "PlexiChat"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "PlexiChat"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PlexiChat Server"),
                x509.NameAttribute(NameOID.COMMON_NAME, domain),
            ])

            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(domain),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())

            # Save certificate and key
            cert_path = self.certs_dir / f"{domain}.crt"
            key_path = self.certs_dir / f"{domain}.key"
            fullchain_path = cert_path  # Same as cert for self-signed

            # Write certificate
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            # Write private key
            with open(key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            # Create certificate info
            cert_info = CertificateInfo(
                domain=domain,
                cert_path=str(cert_path),
                key_path=str(key_path),
                fullchain_path=str(fullchain_path),
                issued_date=datetime.utcnow(),
                expiry_date=datetime.utcnow() + timedelta(days=365),
                issuer="PlexiChat Self-Signed",
                is_self_signed=True,
                auto_renew=config.auto_renew
            )

            self.certificates[domain] = cert_info
            self.save_config()

            logger.info(f"Self-signed certificate generated for: {domain}")
            return True

        except Exception as e:
            logger.error(f"Failed to generate self-signed certificate for {domain}: {e}")
            return False

    def _create_cert_info_letsencrypt(self, domain: str) -> Optional[CertificateInfo]:
        """Create certificate info from Let's Encrypt files."""
        try:
            # Let's Encrypt certificate paths
            le_path = Path(f"/etc/letsencrypt/live/{domain}")
            if not le_path.exists():
                return None

            cert_path = le_path / "cert.pem"
            key_path = le_path / "privkey.pem"
            fullchain_path = le_path / "fullchain.pem"

            if not all(p.exists() for p in [cert_path, key_path, fullchain_path]):
                return None

            # Read certificate to get expiry date
            with open(cert_path, 'rb') as f:
                cert_data = f.read()

            cert = x509.load_pem_x509_certificate(cert_data)

            return CertificateInfo(
                domain=domain,
                cert_path=str(cert_path),
                key_path=str(key_path),
                fullchain_path=str(fullchain_path),
                issued_date=cert.not_valid_before,
                expiry_date=cert.not_valid_after,
                issuer="Let's Encrypt",
                is_self_signed=False,
                auto_renew=True
            )

        except Exception as e:
            logger.error(f"Failed to create cert info for {domain}: {e}")
            return None

    def _check_certbot(self) -> bool:
        """Check if certbot is available."""
        try:
            result = subprocess.run(['certbot', '--version'],
                                  capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False

    async def renew_certificate(self, domain: str) -> bool:
        """Renew certificate for a domain."""
        cert_info = self.certificates.get(domain)
        if not cert_info:
            logger.error(f"No certificate found for domain: {domain}")
            return False

        try:
            cert_info.last_renewal_attempt = datetime.now()

            if cert_info.is_self_signed:
                # Regenerate self-signed certificate
                domain_config = self.domain_configs.get(domain)
                if domain_config:
                    success = await self._generate_self_signed_cert(domain, domain_config)
                else:
                    success = False
            else:
                # Renew Let's Encrypt certificate
                success = await self._renew_letsencrypt_cert(domain)

            if success:
                cert_info.renewal_failures = 0
                logger.info(f"Certificate renewed successfully for: {domain}")
            else:
                cert_info.renewal_failures += 1
                logger.error(f"Certificate renewal failed for: {domain}")

            self.save_config()
            return success

        except Exception as e:
            logger.error(f"Certificate renewal error for {domain}: {e}")
            cert_info.renewal_failures += 1
            self.save_config()
            return False

    async def _renew_letsencrypt_cert(self, domain: str) -> bool:
        """Renew Let's Encrypt certificate."""
        try:
            cmd = ["certbot", "renew", "--cert-name", domain, "--quiet"]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                # Update certificate info
                cert_info = self._create_cert_info_letsencrypt(domain)
                if cert_info:
                    self.certificates[domain] = cert_info
                    return True
            else:
                logger.error(f"Certbot renewal failed for {domain}: {stderr.decode()}")

        except Exception as e:
            logger.error(f"Let's Encrypt renewal failed for {domain}: {e}")

        return False

    def get_ssl_context(self, domain: str) -> Optional[ssl.SSLContext]:
        """Get SSL context for a domain."""
        cert_info = self.certificates.get(domain)
        if not cert_info:
            return None

        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(cert_info.fullchain_path, cert_info.key_path)

            # Enhanced security settings
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            context.options |= ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE

            return context

        except Exception as e:
            logger.error(f"Failed to create SSL context for {domain}: {e}")
            return None

    def check_certificate_expiry(self, domain: str) -> Optional[int]:
        """Check days until certificate expiry."""
        cert_info = self.certificates.get(domain)
        if not cert_info:
            return None

        days_until_expiry = (cert_info.expiry_date - datetime.now()).days
        return days_until_expiry

    def get_certificates_needing_renewal(self) -> List[str]:
        """Get list of certificates that need renewal."""
        needing_renewal = []

        for domain, cert_info in self.certificates.items():
            if not cert_info.auto_renew:
                continue

            domain_config = self.domain_configs.get(domain)
            renewal_days = domain_config.renewal_days_before if domain_config else 30

            days_until_expiry = self.check_certificate_expiry(domain)
            if days_until_expiry is not None and days_until_expiry <= renewal_days:
                needing_renewal.append(domain)

        return needing_renewal

    async def start_renewal_monitoring(self):
        """Start automatic certificate renewal monitoring."""
        if self._renewal_task:
            return

        self._renewal_task = asyncio.create_task(self._renewal_monitor_loop())
        logger.info("Certificate renewal monitoring started")

    async def stop_renewal_monitoring(self):
        """Stop automatic certificate renewal monitoring."""
        if self._renewal_task:
            self._renewal_task.cancel()
            try:
                await self._renewal_task
            except asyncio.CancelledError:
                pass
            self._renewal_task = None
            logger.info("Certificate renewal monitoring stopped")

    async def _renewal_monitor_loop(self):
        """Main renewal monitoring loop."""
        while True:
            try:
                # Check for certificates needing renewal
                needing_renewal = self.get_certificates_needing_renewal()

                for domain in needing_renewal:
                    logger.info(f"Attempting to renew certificate for: {domain}")
                    await self.renew_certificate(domain)

                # Sleep for 24 hours before next check
                await asyncio.sleep(24 * 60 * 60)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in renewal monitoring: {e}")
                await asyncio.sleep(60 * 60)  # Sleep 1 hour on error

    def get_certificate_status(self) -> Dict[str, Any]:
        """Get status of all certificates."""
        status = {
            'certificates': {},
            'total_certificates': len(self.certificates),
            'needing_renewal': len(self.get_certificates_needing_renewal()),
            'last_check': datetime.now().isoformat()
        }

        for domain, cert_info in self.certificates.items():
            days_until_expiry = self.check_certificate_expiry(domain)
            status['certificates'][domain] = {
                'issuer': cert_info.issuer,
                'is_self_signed': cert_info.is_self_signed,
                'issued_date': cert_info.issued_date.isoformat(),
                'expiry_date': cert_info.expiry_date.isoformat(),
                'days_until_expiry': days_until_expiry,
                'auto_renew': cert_info.auto_renew,
                'renewal_failures': cert_info.renewal_failures,
                'last_renewal_attempt': cert_info.last_renewal_attempt.isoformat() if cert_info.last_renewal_attempt else None
            }

        return status
