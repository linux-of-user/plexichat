"""
PlexiChat Certificate Manager - SINGLE SOURCE OF TRUTH

CONSOLIDATED from multiple certificate management systems:
- core_system/security/certificate_manager.py - REMOVED (this file)
- features/security/ssl.py - REMOVED
- features/security/core/certificate_manager.py - REMOVED
- features/security/core/ssl_certificate_manager.py - REMOVED

Features:
- Automated Let's Encrypt certificate generation and renewal
- Self-signed certificate generation for development
- Certificate validation and monitoring
- SSL/TLS context management
- Certificate expiration alerts
- Multi-domain certificate support
- ACME protocol integration
- Certificate backup and recovery
- Unified security integration
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
    certificate_path: Path
    private_key_path: Path
    fullchain_path: Optional[Path] = None
    created_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expiry_date: Optional[datetime] = None
    status: CertificateStatus = CertificateStatus.VALID
    auto_renew: bool = True
    renewal_threshold_days: int = 30
    last_renewal_attempt: Optional[datetime] = None
    renewal_failures: int = 0
    san_domains: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ConsolidatedCertificateManager:
    """
    Consolidated Certificate Manager - Single Source of Truth

    Replaces all previous certificate management systems with a unified,
    comprehensive solution supporting all certificate types and operations.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or getattr(get_config(), "certificates", {})
        self.initialized = False

        # Certificate storage
        self.certificates: Dict[str, CertificateInfo] = {}

        # Configuration
        self.cert_directory = Path(self.config.get("cert_directory", "./certificates"))
        self.lets_encrypt_email = self.config.get("lets_encrypt_email", "admin@example.com")
        self.lets_encrypt_staging = self.config.get("lets_encrypt_staging", False)
        self.auto_renewal_enabled = self.config.get("auto_renewal_enabled", True)
        self.renewal_threshold_days = self.config.get("renewal_threshold_days", 30)
        self.webroot_path = self.config.get("webroot_path", "/var/www/html")

        # ACME configuration
        self.acme_server = "https://acme-v02.api.letsencrypt.org/directory"
        self.acme_staging = "https://acme-staging-v02.api.letsencrypt.org/directory"

        # SSL context cache
        self.ssl_contexts: Dict[str, ssl.SSLContext] = {}

        logger.info("Consolidated Certificate Manager initialized")

    async def initialize(self) -> bool:
        """Initialize the certificate manager."""
        try:
            # Create certificate directory
            self.cert_directory.mkdir(parents=True, exist_ok=True)

            # Load existing certificates
            await self._load_existing_certificates()

            # Start background tasks
            if self.auto_renewal_enabled:
                asyncio.create_task(self._certificate_renewal_task())
                asyncio.create_task(self._certificate_monitoring_task())

            self.initialized = True
            logger.info("✅ Certificate Manager initialized successfully")
            return True

        except Exception as e:
            logger.error(f"❌ Certificate Manager initialization failed: {e}")
            return False

    async def _load_existing_certificates(self) -> None:
        """Load existing certificates from disk."""
        try:
            if not self.cert_directory.exists():
                return

            for cert_file in self.cert_directory.glob("*.crt"):
                domain = cert_file.stem
                key_file = self.cert_directory / f"{domain}.key"

                if key_file.exists():
                    cert_info = await self._create_certificate_info_from_files(
                        domain, cert_file, key_file
                    )
                    if cert_info:
                        self.certificates[domain] = cert_info
                        logger.info(f"Loaded existing certificate for {domain}")

        except Exception as e:
            logger.error(f"Failed to load existing certificates: {e}")

    async def _create_certificate_info_from_files(
        self, domain: str, cert_path: Path, key_path: Path
    ) -> Optional[CertificateInfo]:
        """Create certificate info from existing files."""
        try:
            # Read certificate to get expiry date
            with open(cert_path, 'rb') as f:
                cert_data = f.read()

            cert = x509.load_pem_x509_certificate(cert_data)
            expiry_date = cert.not_valid_after.replace(tzinfo=timezone.utc)

            # Determine certificate type
            cert_type = CertificateType.SELF_SIGNED
            if "Let's Encrypt" in str(cert.issuer):
                cert_type = CertificateType.LETS_ENCRYPT

            return CertificateInfo(
                domain=domain,
                certificate_type=cert_type,
                certificate_path=cert_path,
                private_key_path=key_path,
                expiry_date=expiry_date,
                status=self._get_certificate_status(expiry_date)
            )

        except Exception as e:
            logger.error(f"Failed to create certificate info for {domain}: {e}")
            return None

    def _get_certificate_status(self, expiry_date: datetime) -> CertificateStatus:
        """Get certificate status based on expiry date."""
        if not expiry_date:
            return CertificateStatus.INVALID

        now = datetime.now(timezone.utc)
        days_until_expiry = (expiry_date - now).days

        if days_until_expiry < 0:
            return CertificateStatus.EXPIRED
        elif days_until_expiry <= self.renewal_threshold_days:
            return CertificateStatus.EXPIRING_SOON
        else:
            return CertificateStatus.VALID

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
            return None

    async def _generate_self_signed_certificate(
        self, domain: str, san_domains: Optional[List[str]] = None
    ) -> Optional[CertificateInfo]:
        """Generate a self-signed certificate."""
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PlexiChat"),
                x509.NameAttribute(NameOID.COMMON_NAME, domain),
            ])

            cert_builder = x509.CertificateBuilder()
            cert_builder = cert_builder.subject_name(subject)
            cert_builder = cert_builder.issuer_name(issuer)
            cert_builder = cert_builder.public_key(private_key.public_key())
            cert_builder = cert_builder.serial_number(x509.random_serial_number())
            cert_builder = cert_builder.not_valid_before(datetime.now(timezone.utc))
            cert_builder = cert_builder.not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=365)
            )

            # Add SAN extension
            san_list = [x509.DNSName(domain)]
            if san_domains:
                san_list.extend([x509.DNSName(san) for san in san_domains])

            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )

            # Sign certificate
            certificate = cert_builder.sign(private_key, hashes.SHA256())

            # Save certificate and key
            cert_path = self.cert_directory / f"{domain}.crt"
            key_path = self.cert_directory / f"{domain}.key"

            with open(cert_path, "wb") as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))

            with open(key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            # Create certificate info
            cert_info = CertificateInfo(
                domain=domain,
                certificate_type=CertificateType.SELF_SIGNED,
                certificate_path=cert_path,
                private_key_path=key_path,
                expiry_date=certificate.not_valid_after.replace(tzinfo=timezone.utc),
                san_domains=san_domains or []
            )

            self.certificates[domain] = cert_info
            logger.info(f"Self-signed certificate generated for {domain}")
            return cert_info

        except Exception as e:
            logger.error(f"Failed to generate self-signed certificate for {domain}: {e}")
            return None

    async def _generate_lets_encrypt_certificate(
        self, domain: str, email: Optional[str] = None, san_domains: Optional[List[str]] = None
    ) -> Optional[CertificateInfo]:
        """Generate a Let's Encrypt certificate using certbot."""
        try:
            # Check if certbot is available
            if not shutil.which("certbot"):
                logger.warning("Certbot not available, falling back to self-signed certificate")
                return await self._generate_self_signed_certificate(domain, san_domains)

            email = email or self.lets_encrypt_email
            server_url = self.acme_staging if self.lets_encrypt_staging else self.acme_server

            # Prepare certbot command
            cmd = [
                "certbot", "certonly",
                "--webroot",
                "--webroot-path", self.webroot_path,
                "--email", email,
                "--agree-tos",
                "--no-eff-email",
                "--server", server_url,
                "--cert-name", domain,
                "-d", domain
            ]

            # Add SAN domains
            if san_domains:
                for san in san_domains:
                    cmd.extend(["-d", san])

            if self.lets_encrypt_staging:
                cmd.append("--test-cert")

            # Run certbot
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                # Find certificate files
                cert_path = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
                key_path = Path(f"/etc/letsencrypt/live/{domain}/privkey.pem")

                if cert_path.exists() and key_path.exists():
                    # Copy to our certificate directory
                    local_cert_path = self.cert_directory / f"{domain}.crt"
                    local_key_path = self.cert_directory / f"{domain}.key"

                    shutil.copy2(cert_path, local_cert_path)
                    shutil.copy2(key_path, local_key_path)

                    # Create certificate info
                    cert_info = await self._create_certificate_info_from_files(
                        domain, local_cert_path, local_key_path
                    )

                    if cert_info:
                        cert_info.certificate_type = CertificateType.LETS_ENCRYPT
                        cert_info.san_domains = san_domains or []
                        self.certificates[domain] = cert_info
                        logger.info(f"Let's Encrypt certificate generated for {domain}")
                        return cert_info
            else:
                logger.error(f"Certbot failed for {domain}: {stderr.decode()}")
                # Fallback to self-signed
                return await self._generate_self_signed_certificate(domain, san_domains)

        except Exception as e:
            logger.error(f"Let's Encrypt generation failed for {domain}: {e}")
            return await self._generate_self_signed_certificate(domain, san_domains)

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

    async def _renew_lets_encrypt_certificate(self, domain: str) -> bool:
        """Renew a Let's Encrypt certificate."""
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
                cert_info = self.certificates[domain]
                updated_info = await self._create_certificate_info_from_files(
                    domain, cert_info.certificate_path, cert_info.private_key_path
                )
                if updated_info:
                    updated_info.certificate_type = CertificateType.LETS_ENCRYPT
                    self.certificates[domain] = updated_info
                    # Clear SSL context cache
                    self.ssl_contexts.pop(domain, None)
                    logger.info(f"Let's Encrypt certificate renewed for {domain}")
                    return True
                else:
                    logger.error(f"Certificate info update failed for {domain} after renewal.")
                    return False
            else:
                logger.error(f"Certificate renewal failed for {domain}: {stderr.decode()}")
                return False

        except Exception as e:
            logger.error(f"Let's Encrypt renewal failed for {domain}: {e}")
            return False

    def get_ssl_context(self, domain: str) -> Optional[ssl.SSLContext]:
        """Get SSL context for a domain."""
        if domain in self.ssl_contexts:
            return self.ssl_contexts[domain]

        cert_info = self.certificates.get(domain)
        if not cert_info:
            return None

        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(
                str(cert_info.certificate_path),
                str(cert_info.private_key_path)
            )

            # Enhanced security settings
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            context.options |= ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE

            # Cache the context
            self.ssl_contexts[domain] = context
            return context

        except Exception as e:
            logger.error(f"Failed to create SSL context for {domain}: {e}")
            return None

    def get_certificate_status(self, domain: str) -> Dict[str, Any]:
        """Get certificate status information."""
        cert_info = self.certificates.get(domain)
        if not cert_info:
            return {"error": f"Certificate for {domain} not found"}

        now = datetime.now(timezone.utc)
        days_until_expiry = None

        if cert_info.expiry_date:
            days_until_expiry = (cert_info.expiry_date - now).days

        return {
            "domain": domain,
            "certificate_type": cert_info.certificate_type.value,
            "status": cert_info.status.value,
            "created_date": cert_info.created_date.isoformat(),
            "expiry_date": cert_info.expiry_date.isoformat() if cert_info.expiry_date else None,
            "days_until_expiry": days_until_expiry,
            "auto_renew": cert_info.auto_renew,
            "san_domains": cert_info.san_domains,
            "renewal_failures": cert_info.renewal_failures
        }

    async def _certificate_renewal_task(self) -> None:
        """Background task for certificate renewal."""
        while True:
            try:
                await asyncio.sleep(86400)  # Check daily

                current_time = datetime.now(timezone.utc)

                for domain, cert_info in self.certificates.items():
                    if cert_info.auto_renew and cert_info.expiry_date:
                        # Check if renewal is needed
                        days_until_expiry = (cert_info.expiry_date - current_time).days

                        if days_until_expiry <= cert_info.renewal_threshold_days:
                            logger.info(f"Attempting to renew certificate for {domain}")
                            success = await self.renew_certificate(domain)

                            if success:
                                logger.info(f"Certificate renewed successfully for {domain}")
                            else:
                                logger.error(f"Failed to renew certificate for {domain}")

            except Exception as e:
                logger.error(f"Certificate renewal task error: {e}")

    async def _certificate_monitoring_task(self) -> None:
        """Background task for certificate monitoring."""
        while True:
            try:
                await asyncio.sleep(3600)  # Check every hour

                # Update certificate statuses
                for cert_info in self.certificates.values():
                    if cert_info.expiry_date:
                        cert_info.status = self._get_certificate_status(cert_info.expiry_date)

                # Log warnings for expiring certificates
                expiring_certs = [
                    domain for domain, cert_info in self.certificates.items()
                    if cert_info.status == CertificateStatus.EXPIRING_SOON
                ]

                expired_certs = [
                    domain for domain, cert_info in self.certificates.items()
                    if cert_info.status == CertificateStatus.EXPIRED
                ]

                if expiring_certs:
                    logger.warning(f"Certificates expiring soon: {', '.join(expiring_certs)}")

                if expired_certs:
                    logger.error(f"Expired certificates: {', '.join(expired_certs)}")

            except Exception as e:
                logger.error(f"Certificate monitoring task error: {e}")


# Global instance - SINGLE SOURCE OF TRUTH
_certificate_manager: Optional[ConsolidatedCertificateManager] = None


def get_certificate_manager() -> ConsolidatedCertificateManager:
    """Get the global certificate manager instance."""
    global _certificate_manager
    if _certificate_manager is None:
        _certificate_manager = ConsolidatedCertificateManager()
    return _certificate_manager


# Primary instance
certificate_manager = get_certificate_manager()

# Export main components
__all__ = [
    "ConsolidatedCertificateManager",
    "certificate_manager",
    "CertificateType",
    "CertificateStatus",
    "CertificateInfo",
    "get_certificate_manager"
]