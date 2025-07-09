"""
SSL/TLS configuration and certificate management.
Supports automatic certificate generation, Let's Encrypt integration, and custom certificates.
"""

import os
import ssl
import asyncio
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
import tempfile
import shutil

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import certbot.main
from fastapi import HTTPException

from app.core.config.settings import settings
from app.logger_config import logger

class SSLManager:
    """SSL/TLS certificate manager with automatic renewal."""
    
    def __init__(self):
        self.cert_dir = Path(getattr(settings, 'SSL_CERT_DIR', './ssl'))
        self.cert_dir.mkdir(exist_ok=True)
        
        self.domain = getattr(settings, 'DOMAIN', 'localhost')
        self.email = getattr(settings, 'SSL_EMAIL', 'admin@localhost')
        self.use_letsencrypt = getattr(settings, 'USE_LETSENCRYPT', False)
        self.auto_renew = getattr(settings, 'SSL_AUTO_RENEW', True)
        
        # Certificate paths
        self.cert_file = self.cert_dir / 'cert.pem'
        self.key_file = self.cert_dir / 'key.pem'
        self.chain_file = self.cert_dir / 'chain.pem'
        self.fullchain_file = self.cert_dir / 'fullchain.pem'
        
        # Initialize certificates
        asyncio.create_task(self._initialize_certificates())
        
        # Start renewal monitoring
        if self.auto_renew:
            asyncio.create_task(self._renewal_monitor())
    
    async def _initialize_certificates(self):
        """Initialize SSL certificates."""
        try:
            if self.use_letsencrypt:
                await self._setup_letsencrypt()
            else:
                await self._setup_self_signed()
                
            logger.info("SSL certificates initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize SSL certificates: {e}")
            # Fallback to self-signed
            if self.use_letsencrypt:
                logger.info("Falling back to self-signed certificates")
                await self._setup_self_signed()
    
    async def _setup_letsencrypt(self):
        """Setup Let's Encrypt certificates."""
        if not self._is_valid_domain():
            raise ValueError(f"Invalid domain for Let's Encrypt: {self.domain}")
        
        # Check if certificates already exist and are valid
        if await self._certificates_exist() and await self._certificates_valid():
            logger.info("Valid Let's Encrypt certificates already exist")
            return
        
        logger.info(f"Obtaining Let's Encrypt certificate for {self.domain}")
        
        # Prepare certbot arguments
        certbot_args = [
            'certonly',
            '--standalone',
            '--non-interactive',
            '--agree-tos',
            '--email', self.email,
            '--domains', self.domain,
            '--cert-path', str(self.cert_file),
            '--key-path', str(self.key_file),
            '--chain-path', str(self.chain_file),
            '--fullchain-path', str(self.fullchain_file)
        ]
        
        # Add staging flag for testing
        if getattr(settings, 'LETSENCRYPT_STAGING', False):
            certbot_args.append('--staging')
        
        try:
            # Run certbot
            result = await asyncio.create_subprocess_exec(
                'certbot', *certbot_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                logger.info("Let's Encrypt certificate obtained successfully")
                await self._copy_letsencrypt_certs()
            else:
                error_msg = stderr.decode() if stderr else "Unknown error"
                raise RuntimeError(f"Certbot failed: {error_msg}")
                
        except FileNotFoundError:
            logger.error("Certbot not found. Please install certbot.")
            raise RuntimeError("Certbot not installed")
    
    async def _copy_letsencrypt_certs(self):
        """Copy Let's Encrypt certificates to our cert directory."""
        letsencrypt_dir = Path(f'/etc/letsencrypt/live/{self.domain}')
        
        if letsencrypt_dir.exists():
            # Copy certificates
            shutil.copy2(letsencrypt_dir / 'cert.pem', self.cert_file)
            shutil.copy2(letsencrypt_dir / 'privkey.pem', self.key_file)
            shutil.copy2(letsencrypt_dir / 'chain.pem', self.chain_file)
            shutil.copy2(letsencrypt_dir / 'fullchain.pem', self.fullchain_file)
            
            logger.info("Let's Encrypt certificates copied successfully")
    
    async def _setup_self_signed(self):
        """Setup self-signed certificates."""
        if await self._certificates_exist() and await self._certificates_valid():
            logger.info("Valid self-signed certificates already exist")
            return
        
        logger.info("Generating self-signed SSL certificate")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Chat API"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.domain),
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
                x509.DNSName(self.domain),
                x509.DNSName(f"*.{self.domain}"),
                x509.DNSName("localhost"),
                x509.IPAddress("127.0.0.1"),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Write private key
        with open(self.key_file, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Write certificate
        with open(self.cert_file, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # For self-signed, cert and fullchain are the same
        shutil.copy2(self.cert_file, self.fullchain_file)
        
        # Set proper permissions
        os.chmod(self.key_file, 0o600)
        os.chmod(self.cert_file, 0o644)
        
        logger.info("Self-signed SSL certificate generated successfully")
    
    async def _certificates_exist(self) -> bool:
        """Check if certificate files exist."""
        return (
            self.cert_file.exists() and
            self.key_file.exists() and
            self.fullchain_file.exists()
        )
    
    async def _certificates_valid(self) -> bool:
        """Check if certificates are valid and not expired."""
        try:
            if not await self._certificates_exist():
                return False
            
            # Load certificate
            with open(self.cert_file, 'rb') as f:
                cert_data = f.read()
            
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # Check expiration (renew if expires within 30 days)
            now = datetime.utcnow()
            expires_soon = cert.not_valid_after - timedelta(days=30)
            
            if now >= expires_soon:
                logger.info("Certificate expires soon, renewal needed")
                return False
            
            # Verify certificate matches private key
            with open(self.key_file, 'rb') as f:
                key_data = f.read()
            
            private_key = serialization.load_pem_private_key(
                key_data, password=None, backend=default_backend()
            )
            
            # Simple validation - check if public keys match
            cert_public_key = cert.public_key()
            private_public_key = private_key.public_key()
            
            cert_public_numbers = cert_public_key.public_numbers()
            private_public_numbers = private_public_key.public_numbers()
            
            if cert_public_numbers.n != private_public_numbers.n:
                logger.error("Certificate and private key don't match")
                return False
            
            logger.info(f"Certificate valid until: {cert.not_valid_after}")
            return True
            
        except Exception as e:
            logger.error(f"Certificate validation failed: {e}")
            return False
    
    def _is_valid_domain(self) -> bool:
        """Check if domain is valid for Let's Encrypt."""
        if self.domain in ['localhost', '127.0.0.1']:
            return False
        
        # Basic domain validation
        import re
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        return bool(domain_pattern.match(self.domain))
    
    async def _renewal_monitor(self):
        """Monitor certificates and renew when necessary."""
        while True:
            try:
                await asyncio.sleep(86400)  # Check daily
                
                if not await self._certificates_valid():
                    logger.info("Certificate renewal needed")
                    await self._renew_certificates()
                    
            except Exception as e:
                logger.error(f"Certificate renewal monitor error: {e}")
    
    async def _renew_certificates(self):
        """Renew SSL certificates."""
        try:
            if self.use_letsencrypt:
                await self._renew_letsencrypt()
            else:
                await self._setup_self_signed()
                
            logger.info("SSL certificates renewed successfully")
            
        except Exception as e:
            logger.error(f"Certificate renewal failed: {e}")
    
    async def _renew_letsencrypt(self):
        """Renew Let's Encrypt certificates."""
        logger.info("Renewing Let's Encrypt certificate")
        
        certbot_args = [
            'renew',
            '--non-interactive',
            '--quiet'
        ]
        
        result = await asyncio.create_subprocess_exec(
            'certbot', *certbot_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await result.communicate()
        
        if result.returncode == 0:
            await self._copy_letsencrypt_certs()
            logger.info("Let's Encrypt certificate renewed successfully")
        else:
            error_msg = stderr.decode() if stderr else "Unknown error"
            raise RuntimeError(f"Certificate renewal failed: {error_msg}")
    
    def get_ssl_context(self) -> ssl.SSLContext:
        """Get SSL context for HTTPS server."""
        if not self.cert_file.exists() or not self.key_file.exists():
            raise RuntimeError("SSL certificates not found")
        
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(str(self.fullchain_file), str(self.key_file))
        
        # Security settings
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        context.options |= ssl.OP_SINGLE_DH_USE
        context.options |= ssl.OP_SINGLE_ECDH_USE
        
        return context
    
    def get_certificate_info(self) -> Dict[str, Any]:
        """Get certificate information."""
        try:
            if not self.cert_file.exists():
                return {'status': 'not_found'}
            
            with open(self.cert_file, 'rb') as f:
                cert_data = f.read()
            
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            return {
                'status': 'valid',
                'subject': cert.subject.rfc4514_string(),
                'issuer': cert.issuer.rfc4514_string(),
                'not_valid_before': cert.not_valid_before.isoformat(),
                'not_valid_after': cert.not_valid_after.isoformat(),
                'serial_number': str(cert.serial_number),
                'is_self_signed': cert.issuer == cert.subject,
                'days_until_expiry': (cert.not_valid_after - datetime.utcnow()).days
            }
            
        except Exception as e:
            logger.error(f"Failed to get certificate info: {e}")
            return {'status': 'error', 'error': str(e)}
    
    async def force_renewal(self):
        """Force certificate renewal."""
        logger.info("Forcing SSL certificate renewal")
        await self._renew_certificates()

# Global SSL manager instance
ssl_manager = SSLManager()

def get_ssl_context() -> Optional[ssl.SSLContext]:
    """Get SSL context if HTTPS is enabled."""
    if getattr(settings, 'USE_HTTPS', False):
        try:
            return ssl_manager.get_ssl_context()
        except Exception as e:
            logger.error(f"Failed to create SSL context: {e}")
            return None
    return None
