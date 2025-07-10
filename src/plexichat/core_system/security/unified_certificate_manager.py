"""
Unified Certificate Manager

Consolidates all certificate management functionality from:
- core_system/security/certificate_manager.py
- features/security/ssl.py
- features/security/core/certificate_manager.py
- features/security/core/ssl_certificate_manager.py

Features:
- Automated Let's Encrypt certificate generation and renewal
- Self-signed certificate generation for development
- Certificate validation and monitoring
- SSL/TLS context management
- Certificate expiration alerts
- Multi-domain certificate support
- ACME protocol integration
- Certificate backup and recovery
"""

import asyncio
import ssl
import logging
import subprocess
import shutil
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import secrets

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ...core_system.logging import get_logger
from ...core_system.config import get_config

logger = get_logger(__name__)


class CertificateType(Enum):
    """Types of certificates."""
    SELF_SIGNED = "self_signed"
    LETS_ENCRYPT = "lets_encrypt"
    CUSTOM_CA = "custom_ca"
    WILDCARD = "wildcard"


class CertificateStatus(Enum):
    """Certificate status."""
    VALID = "valid"
    EXPIRED = "expired"
    EXPIRING_SOON = "expiring_soon"
    INVALID = "invalid"
    REVOKED = "revoked"


@dataclass
class CertificateInfo:
    """Certificate information."""
    domain: str
    certificate_type: CertificateType
    cert_path: str
    key_path: str
    fullchain_path: str
    
    # Certificate details
    issued_date: datetime
    expiry_date: datetime
    issuer: str
    subject: str
    serial_number: str
    fingerprint: str
    
    # Configuration
    auto_renew: bool = True
    renewal_threshold_days: int = 30
    
    # Status
    status: CertificateStatus = CertificateStatus.VALID
    last_checked: Optional[datetime] = None
    
    # Metadata
    san_domains: List[str] = field(default_factory=list)
    key_size: int = 2048
    signature_algorithm: str = "sha256"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DomainConfig:
    """Domain configuration for certificate management."""
    domain: str
    use_lets_encrypt: bool = True
    email: str = ""
    webroot_path: str = "/var/www/html"
    auto_renew: bool = True
    san_domains: List[str] = field(default_factory=list)
    challenge_type: str = "http-01"  # http-01, dns-01, tls-alpn-01


class UnifiedCertificateManager:
    """
    Unified Certificate Manager
    
    Provides comprehensive certificate management with automated
    Let's Encrypt integration and enterprise-grade security.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or get_config().get("certificates", {})
        self.initialized = False
        
        # Directories
        self.cert_dir = Path(self.config.get("cert_directory", "data/certificates"))
        self.backup_dir = self.cert_dir / "backups"
        self.temp_dir = self.cert_dir / "temp"
        
        # Certificate storage
        self.certificates: Dict[str, CertificateInfo] = {}
        self.domain_configs: Dict[str, DomainConfig] = {}
        
        # Let's Encrypt configuration
        self.lets_encrypt_email = self.config.get("lets_encrypt_email", "admin@example.com")
        self.lets_encrypt_staging = self.config.get("lets_encrypt_staging", False)
        self.acme_server = (
            "https://acme-staging-v02.api.letsencrypt.org/directory" 
            if self.lets_encrypt_staging 
            else "https://acme-v02.api.letsencrypt.org/directory"
        )
        
        # Renewal settings
        self.auto_renewal_enabled = self.config.get("auto_renewal_enabled", True)
        self.renewal_threshold_days = self.config.get("renewal_threshold_days", 30)
        self.renewal_check_interval = self.config.get("renewal_check_interval", 3600)  # 1 hour
        
        # SSL/TLS settings
        self.min_tls_version = self.config.get("min_tls_version", "1.2")
        self.max_tls_version = self.config.get("max_tls_version", "1.3")
        self.cipher_suites = self.config.get("cipher_suites", 
            "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
        )
        
        logger.info("Unified Certificate Manager initialized")
    
    async def initialize(self) -> None:
        """Initialize the certificate manager."""
        if self.initialized:
            return
        
        # Create directories
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        # Load existing certificates
        await self._load_existing_certificates()
        
        # Load domain configurations
        await self._load_domain_configurations()
        
        # Start background tasks
        if self.auto_renewal_enabled:
            asyncio.create_task(self._certificate_renewal_task())
        
        asyncio.create_task(self._certificate_monitoring_task())
        
        self.initialized = True
        logger.info("Unified Certificate Manager initialized successfully")
    
    async def generate_certificate(
        self,
        domain: str,
        certificate_type: CertificateType = CertificateType.LETS_ENCRYPT,
        email: Optional[str] = None,
        san_domains: Optional[List[str]] = None
    ) -> Optional[CertificateInfo]:
        """Generate a certificate for a domain."""
        if not self.initialized:
            await self.initialize()
        
        logger.info(f"Generating {certificate_type.value} certificate for {domain}")
        
        try:
            if certificate_type == CertificateType.LETS_ENCRYPT:
                return await self._generate_lets_encrypt_certificate(domain, email, san_domains)
            elif certificate_type == CertificateType.SELF_SIGNED:
                return await self._generate_self_signed_certificate(domain, san_domains)
            else:
                raise ValueError(f"Unsupported certificate type: {certificate_type}")
                
        except Exception as e:
            logger.error(f"Failed to generate certificate for {domain}: {e}")
            # Fallback to self-signed if Let's Encrypt fails
            if certificate_type == CertificateType.LETS_ENCRYPT:
                logger.info(f"Falling back to self-signed certificate for {domain}")
                return await self._generate_self_signed_certificate(domain, san_domains)
            return None
    
    async def renew_certificate(self, domain: str) -> bool:
        """Renew a certificate."""
        if domain not in self.certificates:
            logger.error(f"Certificate for {domain} not found")
            return False
        
        cert_info = self.certificates[domain]
        
        try:
            if cert_info.certificate_type == CertificateType.LETS_ENCRYPT:
                return await self._renew_lets_encrypt_certificate(domain)
            elif cert_info.certificate_type == CertificateType.SELF_SIGNED:
                # Regenerate self-signed certificate
                new_cert = await self._generate_self_signed_certificate(domain)
                return new_cert is not None
            else:
                logger.warning(f"Cannot auto-renew {cert_info.certificate_type.value} certificate for {domain}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to renew certificate for {domain}: {e}")
            return False
    
    async def get_ssl_context(self, domain: str) -> Optional[ssl.SSLContext]:
        """Get SSL context for a domain."""
        if domain not in self.certificates:
            logger.warning(f"No certificate found for {domain}")
            return None
        
        cert_info = self.certificates[domain]
        
        try:
            # Create SSL context
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(cert_info.fullchain_path, cert_info.key_path)
            
            # Configure TLS versions
            if self.min_tls_version == "1.2":
                context.minimum_version = ssl.TLSVersion.TLSv1_2
            elif self.min_tls_version == "1.3":
                context.minimum_version = ssl.TLSVersion.TLSv1_3
            
            if self.max_tls_version == "1.3":
                context.maximum_version = ssl.TLSVersion.TLSv1_3
            
            # Configure cipher suites
            context.set_ciphers(self.cipher_suites)
            
            # Security options
            context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            context.options |= ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
            context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
            
            return context
            
        except Exception as e:
            logger.error(f"Failed to create SSL context for {domain}: {e}")
            return None
    
    async def check_certificate_expiration(self) -> Dict[str, Any]:
        """Check certificate expiration status."""
        expiration_report = {
            "total_certificates": len(self.certificates),
            "valid_certificates": 0,
            "expiring_soon": 0,
            "expired_certificates": 0,
            "certificates": []
        }
        
        current_time = datetime.now(timezone.utc)
        
        for domain, cert_info in self.certificates.items():
            # Update certificate status
            await self._update_certificate_status(cert_info)
            
            cert_status = {
                "domain": domain,
                "status": cert_info.status.value,
                "expiry_date": cert_info.expiry_date.isoformat(),
                "days_until_expiry": (cert_info.expiry_date - current_time).days,
                "auto_renew": cert_info.auto_renew
            }
            
            if cert_info.status == CertificateStatus.VALID:
                expiration_report["valid_certificates"] += 1
            elif cert_info.status == CertificateStatus.EXPIRING_SOON:
                expiration_report["expiring_soon"] += 1
            elif cert_info.status == CertificateStatus.EXPIRED:
                expiration_report["expired_certificates"] += 1
            
            expiration_report["certificates"].append(cert_status)
        
        return expiration_report
    
    async def get_certificate_info(self, domain: str) -> Optional[CertificateInfo]:
        """Get certificate information for a domain."""
        return self.certificates.get(domain)
    
    async def list_certificates(self) -> List[CertificateInfo]:
        """List all managed certificates."""
        return list(self.certificates.values())
    
    async def backup_certificates(self) -> str:
        """Create a backup of all certificates."""
        backup_timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_path = self.backup_dir / f"certificates_backup_{backup_timestamp}"
        backup_path.mkdir(parents=True, exist_ok=True)
        
        try:
            # Copy all certificate files
            for domain, cert_info in self.certificates.items():
                domain_backup_dir = backup_path / domain
                domain_backup_dir.mkdir(exist_ok=True)
                
                # Copy certificate files
                if Path(cert_info.cert_path).exists():
                    shutil.copy2(cert_info.cert_path, domain_backup_dir / "cert.pem")
                if Path(cert_info.key_path).exists():
                    shutil.copy2(cert_info.key_path, domain_backup_dir / "key.pem")
                if Path(cert_info.fullchain_path).exists():
                    shutil.copy2(cert_info.fullchain_path, domain_backup_dir / "fullchain.pem")
            
            logger.info(f"Certificate backup created: {backup_path}")
            return str(backup_path)
            
        except Exception as e:
            logger.error(f"Failed to create certificate backup: {e}")
            raise

    # Private Implementation Methods

    async def _generate_lets_encrypt_certificate(
        self,
        domain: str,
        email: Optional[str] = None,
        san_domains: Optional[List[str]] = None
    ) -> Optional[CertificateInfo]:
        """Generate Let's Encrypt certificate using certbot."""
        # Check if certbot is available
        if not shutil.which("certbot"):
            logger.error("Certbot not available, falling back to self-signed")
            return await self._generate_self_signed_certificate(domain, san_domains)

        email = email or self.lets_encrypt_email

        try:
            # Prepare certbot command
            cmd = [
                "certbot", "certonly",
                "--non-interactive",
                "--agree-tos",
                "--email", email,
                "--domains", domain
            ]

            # Add SAN domains
            if san_domains:
                for san_domain in san_domains:
                    cmd.extend(["--domains", san_domain])

            if self.lets_encrypt_staging:
                cmd.append("--staging")

            # Use webroot challenge by default
            domain_config = self.domain_configs.get(domain)
            if domain_config and domain_config.webroot_path:
                cmd.extend(["--webroot", "--webroot-path", domain_config.webroot_path])
            else:
                cmd.append("--standalone")

            # Run certbot
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                # Certificate generated successfully
                cert_info = await self._create_cert_info_from_letsencrypt(domain)
                if cert_info:
                    self.certificates[domain] = cert_info
                    logger.info(f"Let's Encrypt certificate generated for: {domain}")
                    return cert_info
            else:
                logger.error(f"Certbot failed for {domain}: {stderr.decode()}")
                return None

        except Exception as e:
            logger.error(f"Let's Encrypt generation failed for {domain}: {e}")
            return None

    async def _generate_self_signed_certificate(
        self,
        domain: str,
        san_domains: Optional[List[str]] = None,
        key_size: int = 2048,
        validity_days: int = 365
    ) -> Optional[CertificateInfo]:
        """Generate self-signed certificate."""
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )

            # Create certificate subject
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "PlexiChat"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "PlexiChat"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PlexiChat"),
                x509.NameAttribute(NameOID.COMMON_NAME, domain),
            ])

            # Create certificate
            cert_builder = x509.CertificateBuilder()
            cert_builder = cert_builder.subject_name(subject)
            cert_builder = cert_builder.issuer_name(subject)
            cert_builder = cert_builder.public_key(private_key.public_key())
            cert_builder = cert_builder.serial_number(x509.random_serial_number())
            cert_builder = cert_builder.not_valid_before(datetime.now(timezone.utc))
            cert_builder = cert_builder.not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=validity_days)
            )

            # Add SAN extension
            san_list = [x509.DNSName(domain)]
            if san_domains:
                san_list.extend([x509.DNSName(san_domain) for san_domain in san_domains])

            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )

            # Add basic constraints
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )

            # Add key usage
            cert_builder = cert_builder.add_extension(
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
            )

            # Sign certificate
            certificate = cert_builder.sign(private_key, hashes.SHA256())

            # Save certificate and key
            cert_path = self.cert_dir / f"{domain}.crt"
            key_path = self.cert_dir / f"{domain}.key"
            fullchain_path = self.cert_dir / f"{domain}_fullchain.pem"

            # Write certificate
            with open(cert_path, "wb") as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))

            # Write private key
            with open(key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            # Write fullchain (same as cert for self-signed)
            with open(fullchain_path, "wb") as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))

            # Create certificate info
            cert_info = CertificateInfo(
                domain=domain,
                certificate_type=CertificateType.SELF_SIGNED,
                cert_path=str(cert_path),
                key_path=str(key_path),
                fullchain_path=str(fullchain_path),
                issued_date=datetime.now(timezone.utc),
                expiry_date=datetime.now(timezone.utc) + timedelta(days=validity_days),
                issuer="PlexiChat Self-Signed",
                subject=f"CN={domain}",
                serial_number=str(certificate.serial_number),
                fingerprint=certificate.fingerprint(hashes.SHA256()).hex(),
                san_domains=san_domains or [],
                key_size=key_size
            )

            self.certificates[domain] = cert_info
            logger.info(f"Self-signed certificate generated for: {domain}")

            return cert_info

        except Exception as e:
            logger.error(f"Failed to generate self-signed certificate for {domain}: {e}")
            return None
