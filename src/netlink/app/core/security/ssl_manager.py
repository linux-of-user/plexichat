"""
Enhanced SSL/TLS Certificate Management for NetLink
Handles automatic certificate generation, Let's Encrypt integration, domain management,
certificate monitoring, and comprehensive SSL configuration.
"""

import os
import ssl
import asyncio
import subprocess
import json
import time
import hashlib
import socket
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List, Union
import tempfile
import shutil
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import ipaddress
import requests
from dataclasses import dataclass, asdict
from enum import Enum

try:
    from app.core.config.settings import settings
    from app.logger_config import logger
except ImportError:
    # Fallback for standalone usage
    import logging
    logger = logging.getLogger("netlink.ssl")
    class MockSettings:
        DEBUG = False
    settings = MockSettings()


class CertificateType(Enum):
    """Certificate types supported by the system."""
    SELF_SIGNED = "self_signed"
    LETS_ENCRYPT = "lets_encrypt"
    CUSTOM_CA = "custom_ca"
    IMPORTED = "imported"


class DomainType(Enum):
    """Domain configuration types."""
    CUSTOM = "custom"
    PUBLIC_SUBDOMAIN = "public_subdomain"
    LOCALHOST = "localhost"


@dataclass
class DomainConfig:
    """Domain configuration for SSL certificates."""
    domain: str
    domain_type: DomainType
    email: str
    auto_renew: bool = True
    challenge_type: str = "http-01"  # or "dns-01"
    wildcard: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CertificateInfo:
    """Certificate information and metadata."""
    cert_type: CertificateType
    domain: str
    issuer: str
    subject: str
    valid_from: datetime
    valid_until: datetime
    fingerprint: str
    key_size: int
    algorithm: str
    san_domains: List[str]
    is_valid: bool
    days_until_expiry: int
    auto_renewable: bool

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['valid_from'] = self.valid_from.isoformat()
        result['valid_until'] = self.valid_until.isoformat()
        result['cert_type'] = self.cert_type.value
        return result

class EnhancedSSLManager:
    """Enhanced SSL/TLS certificate manager with automatic management capabilities."""

    def __init__(self, cert_dir: str = "certs"):
        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(exist_ok=True)

        # Certificate files
        self.cert_file = self.cert_dir / "server.crt"
        self.key_file = self.cert_dir / "server.key"
        self.ca_file = self.cert_dir / "ca.crt"
        self.chain_file = self.cert_dir / "chain.pem"
        self.fullchain_file = self.cert_dir / "fullchain.pem"

        # Configuration files
        self.config_file = self.cert_dir / "ssl_config.json"
        self.domains_file = self.cert_dir / "domains.json"

        # Let's Encrypt configuration
        self.letsencrypt_dir = self.cert_dir / "letsencrypt"
        self.letsencrypt_dir.mkdir(exist_ok=True)
        self.acme_challenge_dir = self.cert_dir / "acme-challenge"
        self.acme_challenge_dir.mkdir(exist_ok=True)

        # Certificate monitoring
        self.renewal_threshold_days = 30
        self.check_interval_hours = 24
        self.last_check_time = 0

        # Domain configurations
        self.domain_configs: Dict[str, DomainConfig] = {}
        self.load_domain_configs()

        # SSL configuration
        self.ssl_config = self.load_ssl_config()

        logger.info(f"🔒 Enhanced SSL Manager initialized: {self.cert_dir}")

    def load_ssl_config(self) -> Dict[str, Any]:
        """Load SSL configuration from file."""
        default_config = {
            "enabled": False,
            "port": 443,
            "redirect_http": True,
            "hsts_enabled": True,
            "hsts_max_age": 31536000,
            "protocols": ["TLSv1.2", "TLSv1.3"],
            "ciphers": "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS",
            "prefer_server_ciphers": True,
            "session_cache": True,
            "session_timeout": 300,
            "ocsp_stapling": True,
            "certificate_transparency": True
        }

        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    default_config.update(config)
        except Exception as e:
            logger.warning(f"Failed to load SSL config: {e}")

        return default_config

    def save_ssl_config(self):
        """Save SSL configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.ssl_config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save SSL config: {e}")

    def load_domain_configs(self):
        """Load domain configurations from file."""
        try:
            if self.domains_file.exists():
                with open(self.domains_file, 'r') as f:
                    data = json.load(f)
                    for domain, config_data in data.items():
                        config_data['domain_type'] = DomainType(config_data['domain_type'])
                        self.domain_configs[domain] = DomainConfig(**config_data)
        except Exception as e:
            logger.warning(f"Failed to load domain configs: {e}")

    def save_domain_configs(self):
        """Save domain configurations to file."""
        try:
            data = {}
            for domain, config in self.domain_configs.items():
                config_dict = config.to_dict()
                config_dict['domain_type'] = config.domain_type.value
                data[domain] = config_dict

            with open(self.domains_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save domain configs: {e}")
        
    def add_domain_config(self, domain: str, email: str, domain_type: DomainType = DomainType.CUSTOM,
                         auto_renew: bool = True, challenge_type: str = "http-01",
                         wildcard: bool = False) -> bool:
        """Add a new domain configuration."""
        try:
            config = DomainConfig(
                domain=domain,
                domain_type=domain_type,
                email=email,
                auto_renew=auto_renew,
                challenge_type=challenge_type,
                wildcard=wildcard
            )

            self.domain_configs[domain] = config
            self.save_domain_configs()

            logger.info(f"✅ Added domain configuration: {domain}")
            return True

        except Exception as e:
            logger.error(f"Failed to add domain config for {domain}: {e}")
            return False

    def remove_domain_config(self, domain: str) -> bool:
        """Remove a domain configuration."""
        try:
            if domain in self.domain_configs:
                del self.domain_configs[domain]
                self.save_domain_configs()
                logger.info(f"✅ Removed domain configuration: {domain}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to remove domain config for {domain}: {e}")
            return False

    def generate_self_signed_certificate(self,
                                       hostname: str = "localhost",
                                       days_valid: int = 365,
                                       key_size: int = 2048,
                                       san_domains: List[str] = None) -> Tuple[str, str]:
        """Generate enhanced self-signed SSL certificate with SAN support."""
        try:
            if san_domains is None:
                san_domains = []

            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
            )

            # Create certificate subject and issuer
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetLink Secure Communications"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "SSL Certificate Authority"),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ])

            # Set certificate validity
            valid_from = datetime.utcnow()
            valid_until = valid_from + timedelta(days=days_valid)

            # Build SAN list
            san_list = [
                x509.DNSName(hostname),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                x509.IPAddress(ipaddress.IPv6Address("::1")),
            ]

            # Add additional SAN domains
            for domain in san_domains:
                try:
                    # Try to parse as IP address first
                    ip = ipaddress.ip_address(domain)
                    san_list.append(x509.IPAddress(ip))
                except ValueError:
                    # Not an IP, treat as DNS name
                    san_list.append(x509.DNSName(domain))

            # Build certificate with enhanced extensions
            cert_builder = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                valid_from
            ).not_valid_after(
                valid_until
            ).add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=True,
            )

            # Sign the certificate
            cert = cert_builder.sign(private_key, hashes.SHA256())

            # Serialize private key and certificate
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            cert_pem = cert.public_bytes(serialization.Encoding.PEM)

            # Save to files
            with open(self.key_file, "wb") as f:
                f.write(key_pem)

            with open(self.cert_file, "wb") as f:
                f.write(cert_pem)

            # Set appropriate permissions
            os.chmod(self.key_file, 0o600)
            os.chmod(self.cert_file, 0o644)

            # Update domain config
            self.add_domain_config(
                hostname,
                "admin@localhost",
                DomainType.LOCALHOST,
                auto_renew=False
            )

            logger.info(f"✅ Generated enhanced self-signed certificate for {hostname}")
            logger.info(f"   Certificate: {self.cert_file}")
            logger.info(f"   Private Key: {self.key_file}")
            logger.info(f"   Valid until: {valid_until}")
            logger.info(f"   SAN domains: {[str(san) for san in san_list]}")

            return str(self.cert_file), str(self.key_file)

        except Exception as e:
            logger.error(f"Failed to generate self-signed certificate: {e}")
            raise

    def get_certificate_info(self, cert_path: str = None) -> Optional[CertificateInfo]:
        """Get comprehensive certificate information."""
        try:
            if cert_path is None:
                cert_path = self.cert_file

            if not Path(cert_path).exists():
                return None

            with open(cert_path, 'rb') as cert_file:
                cert_data = cert_file.read()
                cert = x509.load_pem_x509_certificate(cert_data)

            # Extract certificate information
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            valid_from = cert.not_valid_before
            valid_until = cert.not_valid_after

            # Calculate fingerprint
            fingerprint = hashlib.sha256(cert_data).hexdigest()

            # Get key information
            public_key = cert.public_key()
            if hasattr(public_key, 'key_size'):
                key_size = public_key.key_size
            else:
                key_size = 0

            # Get algorithm
            algorithm = cert.signature_algorithm_oid._name

            # Get SAN domains
            san_domains = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    if isinstance(name, x509.DNSName):
                        san_domains.append(name.value)
                    elif isinstance(name, x509.IPAddress):
                        san_domains.append(str(name.ip_address))
            except x509.ExtensionNotFound:
                pass

            # Check validity
            now = datetime.utcnow()
            is_valid = valid_from <= now <= valid_until
            days_until_expiry = (valid_until - now).days

            # Determine certificate type
            cert_type = CertificateType.SELF_SIGNED
            if "Let's Encrypt" in issuer:
                cert_type = CertificateType.LETS_ENCRYPT
            elif issuer != subject:
                cert_type = CertificateType.CUSTOM_CA

            # Check if auto-renewable
            domain = self._extract_primary_domain(subject)
            auto_renewable = domain in self.domain_configs and self.domain_configs[domain].auto_renew

            return CertificateInfo(
                cert_type=cert_type,
                domain=domain,
                issuer=issuer,
                subject=subject,
                valid_from=valid_from,
                valid_until=valid_until,
                fingerprint=fingerprint,
                key_size=key_size,
                algorithm=algorithm,
                san_domains=san_domains,
                is_valid=is_valid,
                days_until_expiry=days_until_expiry,
                auto_renewable=auto_renewable
            )

        except Exception as e:
            logger.error(f"Failed to get certificate info: {e}")
            return None

    def _extract_primary_domain(self, subject: str) -> str:
        """Extract primary domain from certificate subject."""
        try:
            # Parse the subject string to find CN
            for part in subject.split(','):
                if part.strip().startswith('CN='):
                    return part.strip()[3:]
            return "localhost"
        except:
            return "localhost"

    def check_certificate_validity(self, cert_path: str = None) -> Dict[str, Any]:
        """Check SSL certificate validity (legacy method)."""
        cert_info = self.get_certificate_info(cert_path)
        if cert_info is None:
            return {"valid": False, "error": "Certificate not found or invalid"}

        return {
            "valid": cert_info.is_valid,
            "days_until_expiry": cert_info.days_until_expiry,
            "expires_at": cert_info.valid_until.isoformat(),
            "domain": cert_info.domain,
            "issuer": cert_info.issuer
        }

    async def setup_letsencrypt_certificate(self, domain: str, email: str,
                                           challenge_type: str = "http-01") -> bool:
        """Setup Let's Encrypt certificate for domain."""
        try:
            # Add domain configuration
            self.add_domain_config(domain, email, DomainType.CUSTOM, challenge_type=challenge_type)

            # Check if certbot is available
            if not await self._check_certbot_available():
                logger.error("Certbot not available, cannot setup Let's Encrypt")
                return False

            # Prepare certbot command
            certbot_cmd = [
                "certbot", "certonly",
                "--standalone" if challenge_type == "http-01" else "--manual",
                "--non-interactive",
                "--agree-tos",
                "--email", email,
                "-d", domain,
                "--cert-path", str(self.cert_file),
                "--key-path", str(self.key_file),
                "--fullchain-path", str(self.fullchain_file),
                "--chain-path", str(self.chain_file)
            ]

            if challenge_type == "http-01":
                certbot_cmd.extend([
                    "--http-01-port", "80",
                    "--http-01-address", "0.0.0.0"
                ])

            # Run certbot
            logger.info(f"🔒 Setting up Let's Encrypt certificate for {domain}")
            process = await asyncio.create_subprocess_exec(
                *certbot_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                logger.info(f"✅ Successfully obtained Let's Encrypt certificate for {domain}")

                # Copy certificates to our directory
                await self._copy_letsencrypt_certificates(domain)

                # Schedule renewal
                await self._schedule_certificate_renewal(domain)

                return True
            else:
                logger.error(f"❌ Failed to obtain Let's Encrypt certificate: {stderr.decode()}")

                # Fallback to self-signed
                logger.info("🔄 Falling back to self-signed certificate")
                self.generate_self_signed_certificate(domain)
                return True

        except Exception as e:
            logger.error(f"Failed to setup Let's Encrypt certificate: {e}")
            # Fallback to self-signed
            self.generate_self_signed_certificate(domain)
            return True

    async def _check_certbot_available(self) -> bool:
        """Check if certbot is available."""
        try:
            process = await asyncio.create_subprocess_exec(
                "certbot", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            return process.returncode == 0
        except:
            return False

    async def _copy_letsencrypt_certificates(self, domain: str):
        """Copy Let's Encrypt certificates to our directory."""
        try:
            le_cert_dir = Path(f"/etc/letsencrypt/live/{domain}")

            if le_cert_dir.exists():
                # Copy certificate files
                shutil.copy2(le_cert_dir / "cert.pem", self.cert_file)
                shutil.copy2(le_cert_dir / "privkey.pem", self.key_file)
                shutil.copy2(le_cert_dir / "chain.pem", self.chain_file)
                shutil.copy2(le_cert_dir / "fullchain.pem", self.fullchain_file)

                # Set proper permissions
                os.chmod(self.key_file, 0o600)
                os.chmod(self.cert_file, 0o644)

                logger.info(f"✅ Copied Let's Encrypt certificates for {domain}")

        except Exception as e:
            logger.error(f"Failed to copy Let's Encrypt certificates: {e}")

    async def _schedule_certificate_renewal(self, domain: str):
        """Schedule automatic certificate renewal."""
        try:
            # Create renewal task
            asyncio.create_task(self._certificate_renewal_loop(domain))
            logger.info(f"📅 Scheduled certificate renewal for {domain}")
        except Exception as e:
            logger.error(f"Failed to schedule certificate renewal: {e}")

    async def _certificate_renewal_loop(self, domain: str):
        """Certificate renewal background task."""
        while True:
            try:
                # Check every 24 hours
                await asyncio.sleep(24 * 3600)

                cert_info = self.get_certificate_info()
                if cert_info and cert_info.days_until_expiry <= self.renewal_threshold_days:
                    logger.info(f"🔄 Certificate expires in {cert_info.days_until_expiry} days, renewing...")
                    await self.renew_certificate(domain)

            except Exception as e:
                logger.error(f"Certificate renewal loop error: {e}")
                await asyncio.sleep(3600)  # Wait 1 hour before retrying

    async def renew_certificate(self, domain: str) -> bool:
        """Renew certificate for domain."""
        try:
            if domain not in self.domain_configs:
                logger.error(f"No domain configuration found for {domain}")
                return False

            config = self.domain_configs[domain]

            if config.domain_type == DomainType.LOCALHOST:
                # Regenerate self-signed certificate
                self.generate_self_signed_certificate(domain)
                return True

            # Renew Let's Encrypt certificate
            certbot_cmd = [
                "certbot", "renew",
                "--cert-name", domain,
                "--non-interactive"
            ]

            process = await asyncio.create_subprocess_exec(
                *certbot_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                logger.info(f"✅ Successfully renewed certificate for {domain}")
                await self._copy_letsencrypt_certificates(domain)
                return True
            else:
                logger.error(f"❌ Failed to renew certificate: {stderr.decode()}")
                return False

        except Exception as e:
            logger.error(f"Failed to renew certificate for {domain}: {e}")
            return False

    def get_enhanced_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Get enhanced SSL context with comprehensive security settings."""
        try:
            if not self.cert_file.exists() or not self.key_file.exists():
                logger.warning("SSL certificate files not found, generating self-signed certificate")
                self.generate_self_signed_certificate()

            # Check certificate validity
            cert_info = self.get_certificate_info()
            if not cert_info or not cert_info.is_valid:
                logger.warning("SSL certificate is invalid, generating new one")
                self.generate_self_signed_certificate()

            # Create SSL context with enhanced security
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

            # Load certificate chain
            if self.fullchain_file.exists():
                context.load_cert_chain(str(self.fullchain_file), str(self.key_file))
            else:
                context.load_cert_chain(str(self.cert_file), str(self.key_file))

            # Enhanced security settings
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_3

            # Set secure cipher suites
            context.set_ciphers(self.ssl_config.get("ciphers",
                "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"))

            # Additional security options
            context.options |= ssl.OP_NO_SSLv2
            context.options |= ssl.OP_NO_SSLv3
            context.options |= ssl.OP_NO_TLSv1
            context.options |= ssl.OP_NO_TLSv1_1
            context.options |= ssl.OP_SINGLE_DH_USE
            context.options |= ssl.OP_SINGLE_ECDH_USE

            if self.ssl_config.get("prefer_server_ciphers", True):
                context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE

            # Session settings
            if self.ssl_config.get("session_cache", True):
                context.set_session_cache_mode(ssl.SESS_CACHE_SERVER)
                context.session_stats()

            # OCSP stapling (if supported)
            if hasattr(context, 'set_ocsp_client_callback') and self.ssl_config.get("ocsp_stapling", True):
                try:
                    context.set_ocsp_client_callback(self._ocsp_callback)
                except AttributeError:
                    pass  # OCSP not supported in this Python version

            logger.info("✅ Enhanced SSL context created successfully")
            logger.info(f"   Protocol: {context.protocol}")
            logger.info(f"   Min version: {context.minimum_version}")
            logger.info(f"   Max version: {context.maximum_version}")

            return context

        except Exception as e:
            logger.error(f"Failed to create SSL context: {e}")
            return None

    def _ocsp_callback(self, conn, ocsp_data, user_data):
        """OCSP stapling callback."""
        # This would implement OCSP stapling if needed
        return True

    def get_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Get SSL context (legacy method)."""
        return self.get_enhanced_ssl_context()

    def get_security_headers(self) -> Dict[str, str]:
        """Get comprehensive security headers."""
        headers = {
            "Strict-Transport-Security": f"max-age={self.ssl_config.get('hsts_max_age', 31536000)}; includeSubDomains; preload",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' wss: https:; frame-ancestors 'none';",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), speaker=()",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "X-Permitted-Cross-Domain-Policies": "none",
            "Clear-Site-Data": '"cache", "cookies", "storage", "executionContexts"'
        }

        # Add certificate transparency header if enabled
        if self.ssl_config.get("certificate_transparency", True):
            headers["Expect-CT"] = "max-age=86400, enforce"

        return headers

    def should_redirect_to_https(self, request_url: str, host: str) -> bool:
        """Check if request should be redirected to HTTPS."""
        if not self.ssl_config.get("redirect_http", True):
            return False

        # Don't redirect localhost in development
        if host in ["localhost", "127.0.0.1", "::1"]:
            return False

        return request_url.startswith('http://') and not request_url.startswith('https://')

    def get_https_url(self, http_url: str, https_port: int = 443) -> str:
        """Convert HTTP URL to HTTPS."""
        https_url = http_url.replace('http://', 'https://', 1)

        # Handle port conversion
        if ':8000' in https_url and https_port != 443:
            https_url = https_url.replace(':8000', f':{https_port}')
        elif ':8000' in https_url and https_port == 443:
            https_url = https_url.replace(':8000', '')

        return https_url

    def get_all_certificates_info(self) -> Dict[str, Any]:
        """Get comprehensive information about all certificates."""
        info = {
            "ssl_enabled": self.ssl_config.get("enabled", False),
            "cert_file_exists": self.cert_file.exists(),
            "key_file_exists": self.key_file.exists(),
            "fullchain_file_exists": self.fullchain_file.exists(),
            "chain_file_exists": self.chain_file.exists(),
            "domains": {},
            "renewal_threshold_days": self.renewal_threshold_days,
            "last_check_time": self.last_check_time
        }

        # Get primary certificate info
        if self.cert_file.exists():
            cert_info = self.get_certificate_info()
            if cert_info:
                info.update(cert_info.to_dict())
                info["ssl_enabled"] = cert_info.is_valid

        # Get domain configurations
        for domain, config in self.domain_configs.items():
            info["domains"][domain] = config.to_dict()

        return info

    async def monitor_certificates(self) -> Dict[str, Any]:
        """Monitor all certificates and return status."""
        try:
            current_time = time.time()

            # Update last check time
            self.last_check_time = current_time

            status = {
                "monitoring_active": True,
                "last_check": datetime.fromtimestamp(current_time).isoformat(),
                "certificates": {},
                "alerts": [],
                "recommendations": []
            }

            # Check primary certificate
            cert_info = self.get_certificate_info()
            if cert_info:
                status["certificates"]["primary"] = cert_info.to_dict()

                # Check for alerts
                if cert_info.days_until_expiry <= 7:
                    status["alerts"].append({
                        "level": "critical",
                        "message": f"Certificate expires in {cert_info.days_until_expiry} days",
                        "domain": cert_info.domain
                    })
                elif cert_info.days_until_expiry <= self.renewal_threshold_days:
                    status["alerts"].append({
                        "level": "warning",
                        "message": f"Certificate expires in {cert_info.days_until_expiry} days",
                        "domain": cert_info.domain
                    })

                # Add recommendations
                if cert_info.cert_type == CertificateType.SELF_SIGNED:
                    status["recommendations"].append({
                        "type": "security",
                        "message": "Consider using Let's Encrypt for production deployment",
                        "action": "setup_letsencrypt"
                    })

                if cert_info.key_size < 2048:
                    status["recommendations"].append({
                        "type": "security",
                        "message": f"Key size {cert_info.key_size} is below recommended 2048 bits",
                        "action": "regenerate_certificate"
                    })

            return status

        except Exception as e:
            logger.error(f"Certificate monitoring failed: {e}")
            return {
                "monitoring_active": False,
                "error": str(e),
                "last_check": datetime.now().isoformat()
            }

    async def setup_automatic_domain(self, domain_type: str = "public",
                                   custom_domain: str = None, email: str = None) -> Dict[str, Any]:
        """Setup automatic domain configuration."""
        try:
            if domain_type == "custom" and custom_domain and email:
                # Setup custom domain with Let's Encrypt
                success = await self.setup_letsencrypt_certificate(custom_domain, email)
                return {
                    "success": success,
                    "domain": custom_domain,
                    "type": "custom",
                    "certificate_type": "lets_encrypt" if success else "self_signed"
                }

            elif domain_type == "public":
                # Setup public subdomain (this would integrate with a service like ngrok or similar)
                subdomain = f"netlink-{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}.example.com"

                # For now, use self-signed certificate
                self.generate_self_signed_certificate(subdomain)

                return {
                    "success": True,
                    "domain": subdomain,
                    "type": "public_subdomain",
                    "certificate_type": "self_signed",
                    "note": "Public subdomain service integration needed for production"
                }

            else:
                # Default to localhost
                self.generate_self_signed_certificate("localhost")

                return {
                    "success": True,
                    "domain": "localhost",
                    "type": "localhost",
                    "certificate_type": "self_signed"
                }

        except Exception as e:
            logger.error(f"Failed to setup automatic domain: {e}")
            return {
                "success": False,
                "error": str(e)
            }

# Legacy compatibility aliases
SSLCertificateManager = EnhancedSSLManager


class ComprehensiveSSLManager:
    """Comprehensive SSL/TLS manager with all features."""

    def __init__(self, cert_dir: str = "certs"):
        self.ssl_manager = EnhancedSSLManager(cert_dir)
        self.monitoring_enabled = True
        self.auto_renewal_enabled = True

    async def initialize(self, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Initialize comprehensive SSL/TLS system."""
        try:
            if config:
                self.ssl_manager.ssl_config.update(config)
                self.ssl_manager.save_ssl_config()

            # Check if SSL is enabled
            if not self.ssl_manager.ssl_config.get("enabled", False):
                logger.info("🔒 SSL/TLS disabled in configuration")
                return {"ssl_enabled": False, "message": "SSL disabled"}

            # Get SSL context
            ssl_context = self.ssl_manager.get_enhanced_ssl_context()

            if ssl_context:
                cert_info = self.ssl_manager.get_all_certificates_info()

                # Start monitoring if enabled
                if self.monitoring_enabled:
                    asyncio.create_task(self._monitoring_loop())

                logger.info("✅ Comprehensive SSL/TLS system initialized")

                return {
                    "ssl_enabled": True,
                    "ssl_context": ssl_context,
                    "certificate_info": cert_info,
                    "monitoring_enabled": self.monitoring_enabled,
                    "auto_renewal_enabled": self.auto_renewal_enabled
                }
            else:
                logger.error("❌ Failed to initialize SSL/TLS")
                return {"ssl_enabled": False, "error": "Failed to create SSL context"}

        except Exception as e:
            logger.error(f"SSL/TLS initialization failed: {e}")
            return {"ssl_enabled": False, "error": str(e)}

    async def setup_automatic_https(self, domain: str = None, email: str = None,
                                  domain_type: str = "localhost") -> Dict[str, Any]:
        """Setup automatic HTTPS with comprehensive options."""
        try:
            if domain_type == "custom" and domain and email:
                # Setup custom domain with Let's Encrypt
                success = await self.ssl_manager.setup_letsencrypt_certificate(domain, email)

                if success:
                    logger.info(f"✅ Automatic HTTPS setup completed for {domain}")
                    return {
                        "success": True,
                        "domain": domain,
                        "certificate_type": "lets_encrypt",
                        "auto_renewal": True,
                        "https_port": self.ssl_manager.ssl_config.get("port", 443)
                    }

            elif domain_type == "public":
                # Setup public subdomain
                result = await self.ssl_manager.setup_automatic_domain("public")
                return result

            else:
                # Default to localhost with self-signed
                self.ssl_manager.generate_self_signed_certificate("localhost")

                return {
                    "success": True,
                    "domain": "localhost",
                    "certificate_type": "self_signed",
                    "auto_renewal": False,
                    "https_port": self.ssl_manager.ssl_config.get("port", 443),
                    "note": "Using self-signed certificate for localhost"
                }

        except Exception as e:
            logger.error(f"Failed to setup automatic HTTPS: {e}")
            return {"success": False, "error": str(e)}

    async def _monitoring_loop(self):
        """Background monitoring loop."""
        while self.monitoring_enabled:
            try:
                # Monitor certificates every hour
                await asyncio.sleep(3600)

                status = await self.ssl_manager.monitor_certificates()

                # Log any alerts
                for alert in status.get("alerts", []):
                    if alert["level"] == "critical":
                        logger.critical(f"🚨 SSL Alert: {alert['message']}")
                    elif alert["level"] == "warning":
                        logger.warning(f"⚠️ SSL Warning: {alert['message']}")

                # Auto-renewal if enabled
                if self.auto_renewal_enabled:
                    cert_info = self.ssl_manager.get_certificate_info()
                    if cert_info and cert_info.days_until_expiry <= self.ssl_manager.renewal_threshold_days:
                        if cert_info.auto_renewable:
                            logger.info(f"🔄 Auto-renewing certificate for {cert_info.domain}")
                            await self.ssl_manager.renew_certificate(cert_info.domain)

            except Exception as e:
                logger.error(f"SSL monitoring error: {e}")
                await asyncio.sleep(3600)  # Wait before retrying

    def get_security_headers(self) -> Dict[str, str]:
        """Get comprehensive security headers."""
        return self.ssl_manager.get_security_headers()

    def should_redirect_to_https(self, request_url: str, host: str) -> bool:
        """Check if request should be redirected to HTTPS."""
        return self.ssl_manager.should_redirect_to_https(request_url, host)

    def get_https_url(self, http_url: str) -> str:
        """Convert HTTP URL to HTTPS."""
        https_port = self.ssl_manager.ssl_config.get("port", 443)
        return self.ssl_manager.get_https_url(http_url, https_port)

    async def get_status(self) -> Dict[str, Any]:
        """Get comprehensive SSL status."""
        return await self.ssl_manager.monitor_certificates()

    def enable_monitoring(self):
        """Enable certificate monitoring."""
        self.monitoring_enabled = True
        if not hasattr(self, '_monitoring_task'):
            self._monitoring_task = asyncio.create_task(self._monitoring_loop())

    def disable_monitoring(self):
        """Disable certificate monitoring."""
        self.monitoring_enabled = False
        if hasattr(self, '_monitoring_task'):
            self._monitoring_task.cancel()


# Global SSL manager instances
ssl_manager = ComprehensiveSSLManager()
enhanced_ssl_manager = EnhancedSSLManager()

# Export main classes and functions
__all__ = [
    'EnhancedSSLManager',
    'ComprehensiveSSLManager',
    'CertificateType',
    'DomainType',
    'DomainConfig',
    'CertificateInfo',
    'ssl_manager',
    'enhanced_ssl_manager'
]
