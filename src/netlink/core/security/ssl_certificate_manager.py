"""
NetLink SSL Certificate Manager

Comprehensive SSL/TLS certificate management with Let's Encrypt integration,
automatic renewal, and certificate monitoring.
"""

import asyncio
import logging
import ssl
import socket
import subprocess
import tempfile
import shutil
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import requests

logger = logging.getLogger(__name__)


class CertificateStatus(Enum):
    """Certificate status."""
    VALID = "valid"
    EXPIRED = "expired"
    EXPIRING_SOON = "expiring_soon"
    INVALID = "invalid"
    REVOKED = "revoked"
    PENDING = "pending"


class CertificateType(Enum):
    """Certificate types."""
    SELF_SIGNED = "self_signed"
    LETS_ENCRYPT = "lets_encrypt"
    COMMERCIAL = "commercial"
    INTERNAL_CA = "internal_ca"


@dataclass
class Certificate:
    """Represents an SSL certificate."""
    domain: str
    certificate_path: str
    private_key_path: str
    certificate_type: CertificateType
    issued_date: datetime
    expiry_date: datetime
    issuer: str
    subject: str
    serial_number: str
    fingerprint: str
    status: CertificateStatus = CertificateStatus.VALID
    auto_renew: bool = True
    
    @property
    def days_until_expiry(self) -> int:
        """Days until certificate expires."""
        return (self.expiry_date - datetime.now(timezone.utc)).days
    
    @property
    def is_expired(self) -> bool:
        """Check if certificate is expired."""
        return datetime.now(timezone.utc) > self.expiry_date
    
    @property
    def is_expiring_soon(self) -> bool:
        """Check if certificate is expiring soon (within 30 days)."""
        return self.days_until_expiry <= 30
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert certificate to dictionary."""
        return {
            "domain": self.domain,
            "certificate_path": self.certificate_path,
            "private_key_path": self.private_key_path,
            "certificate_type": self.certificate_type.value,
            "issued_date": self.issued_date.isoformat(),
            "expiry_date": self.expiry_date.isoformat(),
            "issuer": self.issuer,
            "subject": self.subject,
            "serial_number": self.serial_number,
            "fingerprint": self.fingerprint,
            "status": self.status.value,
            "auto_renew": self.auto_renew,
            "days_until_expiry": self.days_until_expiry,
            "is_expired": self.is_expired,
            "is_expiring_soon": self.is_expiring_soon
        }


class SSLCertificateManager:
    """Comprehensive SSL certificate management system."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize SSL certificate manager."""
        self.config = config or {}
        self.certificates: Dict[str, Certificate] = {}
        
        # Configuration
        self.cert_directory = Path(self.config.get("cert_directory", "/etc/ssl/netlink"))
        self.lets_encrypt_email = self.config.get("lets_encrypt_email", "admin@example.com")
        self.lets_encrypt_staging = self.config.get("lets_encrypt_staging", False)
        self.auto_renewal_enabled = self.config.get("auto_renewal_enabled", True)
        self.renewal_threshold_days = self.config.get("renewal_threshold_days", 30)
        
        # Ensure certificate directory exists
        self.cert_directory.mkdir(parents=True, exist_ok=True)
        
        # ACME client configuration
        self.acme_server = "https://acme-staging-v02.api.letsencrypt.org/directory" if self.lets_encrypt_staging else "https://acme-v02.api.letsencrypt.org/directory"
        
        logger.info("SSL Certificate Manager initialized")
    
    async def generate_self_signed_certificate(self, domain: str, key_size: int = 2048, validity_days: int = 365) -> Certificate:
        """Generate a self-signed certificate."""
        logger.info(f"Generating self-signed certificate for {domain}")
        
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            
            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "NetLink"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "NetLink"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetLink Security"),
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
                datetime.now(timezone.utc)
            ).not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=validity_days)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(domain),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256(), default_backend())
            
            # Save certificate and private key
            cert_path = self.cert_directory / f"{domain}.crt"
            key_path = self.cert_directory / f"{domain}.key"
            
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            with open(key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Set proper permissions
            key_path.chmod(0o600)
            cert_path.chmod(0o644)
            
            # Create certificate object
            certificate = Certificate(
                domain=domain,
                certificate_path=str(cert_path),
                private_key_path=str(key_path),
                certificate_type=CertificateType.SELF_SIGNED,
                issued_date=datetime.now(timezone.utc),
                expiry_date=datetime.now(timezone.utc) + timedelta(days=validity_days),
                issuer=f"CN={domain}",
                subject=f"CN={domain}",
                serial_number=str(cert.serial_number),
                fingerprint=cert.fingerprint(hashes.SHA256()).hex()
            )
            
            self.certificates[domain] = certificate
            logger.info(f"Self-signed certificate generated for {domain}")
            
            return certificate
            
        except Exception as e:
            logger.error(f"Failed to generate self-signed certificate for {domain}: {e}")
            raise
    
    async def request_lets_encrypt_certificate(self, domain: str, webroot_path: Optional[str] = None) -> Certificate:
        """Request a Let's Encrypt certificate."""
        logger.info(f"Requesting Let's Encrypt certificate for {domain}")
        
        try:
            # Check if certbot is available
            if not shutil.which("certbot"):
                raise Exception("Certbot is not installed. Please install certbot to use Let's Encrypt certificates.")
            
            # Prepare certbot command
            cmd = [
                "certbot", "certonly",
                "--non-interactive",
                "--agree-tos",
                "--email", self.lets_encrypt_email,
                "--domains", domain
            ]
            
            if self.lets_encrypt_staging:
                cmd.append("--staging")
            
            if webroot_path:
                cmd.extend(["--webroot", "--webroot-path", webroot_path])
            else:
                cmd.append("--standalone")
            
            # Run certbot
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(f"Certbot failed: {result.stderr}")
            
            # Find certificate files
            cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
            key_path = f"/etc/letsencrypt/live/{domain}/privkey.pem"
            
            if not Path(cert_path).exists() or not Path(key_path).exists():
                raise Exception("Certificate files not found after certbot execution")
            
            # Parse certificate
            certificate = await self._parse_certificate_file(cert_path, key_path, CertificateType.LETS_ENCRYPT)
            certificate.domain = domain
            
            self.certificates[domain] = certificate
            logger.info(f"Let's Encrypt certificate obtained for {domain}")
            
            return certificate
            
        except Exception as e:
            logger.error(f"Failed to request Let's Encrypt certificate for {domain}: {e}")
            raise
    
    async def _parse_certificate_file(self, cert_path: str, key_path: str, cert_type: CertificateType) -> Certificate:
        """Parse certificate file and extract information."""
        try:
            with open(cert_path, "rb") as f:
                cert_data = f.read()
            
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # Extract certificate information
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            serial_number = str(cert.serial_number)
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            
            # Get domain from subject
            domain = None
            for attribute in cert.subject:
                if attribute.oid == NameOID.COMMON_NAME:
                    domain = attribute.value
                    break
            
            if not domain:
                raise Exception("Could not extract domain from certificate")
            
            certificate = Certificate(
                domain=domain,
                certificate_path=cert_path,
                private_key_path=key_path,
                certificate_type=cert_type,
                issued_date=cert.not_valid_before.replace(tzinfo=timezone.utc),
                expiry_date=cert.not_valid_after.replace(tzinfo=timezone.utc),
                issuer=issuer,
                subject=subject,
                serial_number=serial_number,
                fingerprint=fingerprint
            )
            
            # Update status
            certificate.status = self._determine_certificate_status(certificate)
            
            return certificate
            
        except Exception as e:
            logger.error(f"Failed to parse certificate file {cert_path}: {e}")
            raise
    
    def _determine_certificate_status(self, certificate: Certificate) -> CertificateStatus:
        """Determine certificate status."""
        if certificate.is_expired:
            return CertificateStatus.EXPIRED
        elif certificate.is_expiring_soon:
            return CertificateStatus.EXPIRING_SOON
        else:
            return CertificateStatus.VALID
    
    async def load_existing_certificates(self):
        """Load existing certificates from the certificate directory."""
        logger.info("Loading existing certificates")
        
        try:
            for cert_file in self.cert_directory.glob("*.crt"):
                domain = cert_file.stem
                key_file = self.cert_directory / f"{domain}.key"
                
                if key_file.exists():
                    try:
                        certificate = await self._parse_certificate_file(
                            str(cert_file), 
                            str(key_file), 
                            CertificateType.SELF_SIGNED
                        )
                        self.certificates[domain] = certificate
                        logger.info(f"Loaded certificate for {domain}")
                    except Exception as e:
                        logger.error(f"Failed to load certificate for {domain}: {e}")
            
            # Also check Let's Encrypt certificates
            letsencrypt_dir = Path("/etc/letsencrypt/live")
            if letsencrypt_dir.exists():
                for domain_dir in letsencrypt_dir.iterdir():
                    if domain_dir.is_dir():
                        cert_file = domain_dir / "fullchain.pem"
                        key_file = domain_dir / "privkey.pem"
                        
                        if cert_file.exists() and key_file.exists():
                            try:
                                certificate = await self._parse_certificate_file(
                                    str(cert_file),
                                    str(key_file),
                                    CertificateType.LETS_ENCRYPT
                                )
                                self.certificates[domain_dir.name] = certificate
                                logger.info(f"Loaded Let's Encrypt certificate for {domain_dir.name}")
                            except Exception as e:
                                logger.error(f"Failed to load Let's Encrypt certificate for {domain_dir.name}: {e}")
                                
        except Exception as e:
            logger.error(f"Failed to load existing certificates: {e}")
    
    async def renew_certificate(self, domain: str) -> bool:
        """Renew a certificate."""
        logger.info(f"Renewing certificate for {domain}")
        
        certificate = self.certificates.get(domain)
        if not certificate:
            logger.error(f"Certificate for {domain} not found")
            return False
        
        try:
            if certificate.certificate_type == CertificateType.LETS_ENCRYPT:
                # Renew Let's Encrypt certificate
                cmd = ["certbot", "renew", "--cert-name", domain, "--non-interactive"]
                if self.lets_encrypt_staging:
                    cmd.append("--staging")
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    # Reload certificate
                    cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
                    key_path = f"/etc/letsencrypt/live/{domain}/privkey.pem"
                    
                    renewed_cert = await self._parse_certificate_file(cert_path, key_path, CertificateType.LETS_ENCRYPT)
                    renewed_cert.domain = domain
                    self.certificates[domain] = renewed_cert
                    
                    logger.info(f"Let's Encrypt certificate renewed for {domain}")
                    return True
                else:
                    logger.error(f"Failed to renew Let's Encrypt certificate for {domain}: {result.stderr}")
                    return False
            
            elif certificate.certificate_type == CertificateType.SELF_SIGNED:
                # Regenerate self-signed certificate
                new_cert = await self.generate_self_signed_certificate(domain)
                logger.info(f"Self-signed certificate renewed for {domain}")
                return True
            
            else:
                logger.warning(f"Cannot auto-renew {certificate.certificate_type.value} certificate for {domain}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to renew certificate for {domain}: {e}")
            return False

    async def check_certificate_validity(self, domain: str) -> Dict[str, Any]:
        """Check certificate validity and return detailed information."""
        certificate = self.certificates.get(domain)
        if not certificate:
            return {"error": f"Certificate for {domain} not found"}

        try:
            # Update certificate status
            certificate.status = self._determine_certificate_status(certificate)

            # Check if certificate file still exists
            cert_exists = Path(certificate.certificate_path).exists()
            key_exists = Path(certificate.private_key_path).exists()

            # Test SSL connection if it's a web certificate
            ssl_test_result = await self._test_ssl_connection(domain)

            return {
                "domain": domain,
                "status": certificate.status.value,
                "days_until_expiry": certificate.days_until_expiry,
                "is_expired": certificate.is_expired,
                "is_expiring_soon": certificate.is_expiring_soon,
                "certificate_exists": cert_exists,
                "private_key_exists": key_exists,
                "ssl_connection_test": ssl_test_result,
                "certificate_info": certificate.to_dict()
            }

        except Exception as e:
            logger.error(f"Failed to check certificate validity for {domain}: {e}")
            return {"error": str(e)}

    async def _test_ssl_connection(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """Test SSL connection to domain."""
        try:
            context = ssl.create_default_context()

            with socket.create_connection((domain, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    return {
                        "success": True,
                        "tls_version": version,
                        "cipher_suite": cipher[0] if cipher else None,
                        "certificate_matches": cert.get('subject', [[]])[0][0][1] == domain if cert else False
                    }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def auto_renew_certificates(self) -> Dict[str, bool]:
        """Automatically renew certificates that are expiring soon."""
        logger.info("Starting automatic certificate renewal")

        renewal_results = {}

        for domain, certificate in self.certificates.items():
            if certificate.auto_renew and certificate.is_expiring_soon and not certificate.is_expired:
                logger.info(f"Certificate for {domain} is expiring in {certificate.days_until_expiry} days, attempting renewal")
                renewal_results[domain] = await self.renew_certificate(domain)
            elif certificate.is_expired:
                logger.warning(f"Certificate for {domain} has already expired")
                renewal_results[domain] = False

        return renewal_results

    async def revoke_certificate(self, domain: str) -> bool:
        """Revoke a certificate."""
        logger.info(f"Revoking certificate for {domain}")

        certificate = self.certificates.get(domain)
        if not certificate:
            logger.error(f"Certificate for {domain} not found")
            return False

        try:
            if certificate.certificate_type == CertificateType.LETS_ENCRYPT:
                # Revoke Let's Encrypt certificate
                cmd = [
                    "certbot", "revoke",
                    "--cert-path", certificate.certificate_path,
                    "--non-interactive"
                ]

                if self.lets_encrypt_staging:
                    cmd.append("--staging")

                result = subprocess.run(cmd, capture_output=True, text=True)

                if result.returncode == 0:
                    certificate.status = CertificateStatus.REVOKED
                    logger.info(f"Let's Encrypt certificate revoked for {domain}")
                    return True
                else:
                    logger.error(f"Failed to revoke Let's Encrypt certificate for {domain}: {result.stderr}")
                    return False

            else:
                # For self-signed certificates, just mark as revoked
                certificate.status = CertificateStatus.REVOKED
                logger.info(f"Certificate marked as revoked for {domain}")
                return True

        except Exception as e:
            logger.error(f"Failed to revoke certificate for {domain}: {e}")
            return False

    async def delete_certificate(self, domain: str) -> bool:
        """Delete a certificate and its private key."""
        logger.info(f"Deleting certificate for {domain}")

        certificate = self.certificates.get(domain)
        if not certificate:
            logger.error(f"Certificate for {domain} not found")
            return False

        try:
            # Delete certificate files
            cert_path = Path(certificate.certificate_path)
            key_path = Path(certificate.private_key_path)

            if cert_path.exists():
                cert_path.unlink()

            if key_path.exists():
                key_path.unlink()

            # Remove from certificates dict
            del self.certificates[domain]

            logger.info(f"Certificate deleted for {domain}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete certificate for {domain}: {e}")
            return False

    async def list_certificates(self) -> List[Dict[str, Any]]:
        """List all managed certificates."""
        certificates = []

        for domain, certificate in self.certificates.items():
            # Update status
            certificate.status = self._determine_certificate_status(certificate)
            certificates.append(certificate.to_dict())

        return certificates

    async def get_certificate_info(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get detailed certificate information."""
        certificate = self.certificates.get(domain)
        if not certificate:
            return None

        # Update status
        certificate.status = self._determine_certificate_status(certificate)
        return certificate.to_dict()

    async def get_certificate_health_report(self) -> Dict[str, Any]:
        """Generate a comprehensive certificate health report."""
        report = {
            "total_certificates": len(self.certificates),
            "valid_certificates": 0,
            "expired_certificates": 0,
            "expiring_soon_certificates": 0,
            "revoked_certificates": 0,
            "certificates_by_type": {},
            "renewal_recommendations": [],
            "security_warnings": []
        }

        for domain, certificate in self.certificates.items():
            # Update status
            certificate.status = self._determine_certificate_status(certificate)

            # Count by status
            if certificate.status == CertificateStatus.VALID:
                report["valid_certificates"] += 1
            elif certificate.status == CertificateStatus.EXPIRED:
                report["expired_certificates"] += 1
            elif certificate.status == CertificateStatus.EXPIRING_SOON:
                report["expiring_soon_certificates"] += 1
            elif certificate.status == CertificateStatus.REVOKED:
                report["revoked_certificates"] += 1

            # Count by type
            cert_type = certificate.certificate_type.value
            report["certificates_by_type"][cert_type] = report["certificates_by_type"].get(cert_type, 0) + 1

            # Generate recommendations
            if certificate.is_expiring_soon and not certificate.is_expired:
                report["renewal_recommendations"].append(f"Certificate for {domain} expires in {certificate.days_until_expiry} days")

            if certificate.is_expired:
                report["renewal_recommendations"].append(f"Certificate for {domain} has expired and needs immediate renewal")

            # Security warnings
            if certificate.certificate_type == CertificateType.SELF_SIGNED:
                report["security_warnings"].append(f"Self-signed certificate for {domain} - consider using a trusted CA")

        return report


# Global instance
ssl_manager = SSLCertificateManager()
