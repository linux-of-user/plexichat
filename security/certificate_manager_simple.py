import asyncio
import logging
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pathlib import Path

logger = logging.getLogger(__name__)


class CertificateType(Enum):
    """Certificate types."""
    SSL_TLS = "ssl_tls"
    CLIENT = "client"
    CA = "ca"
    INTERMEDIATE = "intermediate"


class CertificateStatus(Enum):
    """Certificate status."""
    VALID = "valid"
    EXPIRED = "expired"
    EXPIRING_SOON = "expiring_soon"
    REVOKED = "revoked"
    INVALID = "invalid"


@dataclass
class CertificateInfo:
    """Certificate information."""
    certificate_id: str
    common_name: str
    certificate_type: CertificateType
    status: CertificateStatus
    issued_date: datetime
    expiry_date: datetime
    issuer: str = ""
    subject: str = ""
    serial_number: str = ""
    fingerprint: str = ""
    key_size: int = 2048
    signature_algorithm: str = "SHA256withRSA"
    san_list: List[str] = field(default_factory=list)
    certificate_path: Optional[str] = None
    private_key_path: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class CertificateManager:
    """Simplified certificate management system."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.certificates: Dict[str, CertificateInfo] = {}
        self.certificate_store_path = self.config.get("store_path", "./certificates")
        self.auto_renewal_enabled = self.config.get("auto_renewal", True)
        self.renewal_threshold_days = self.config.get("renewal_threshold_days", 30)
        self.monitoring_enabled = self.config.get("monitoring_enabled", True)
        self.background_tasks: List[asyncio.Task] = []
        
    async def initialize(self):
        """Initialize the certificate manager."""
        try:
            # Create certificate store directory
            Path(self.certificate_store_path).mkdir(parents=True, exist_ok=True)
            
            # Load existing certificates
            await self._load_certificates()
            
            # Start background monitoring if enabled
            if self.monitoring_enabled:
                self.background_tasks.append(
                    asyncio.create_task(self._certificate_monitoring_loop())
                )
            
            logger.info("Certificate manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize certificate manager: {e}")
            raise
    
    async def _load_certificates(self):
        """Load certificates from the certificate store."""
        try:
            store_path = Path(self.certificate_store_path)
            if not store_path.exists():
                return
            
            # In a real implementation, would scan for certificate files
            # and load their metadata
            logger.info("Certificate store loaded")
            
        except Exception as e:
            logger.error(f"Failed to load certificates: {e}")
    
    async def create_certificate(self, common_name: str, 
                               certificate_type: CertificateType = CertificateType.SSL_TLS,
                               validity_days: int = 365,
                               key_size: int = 2048,
                               san_list: Optional[List[str]] = None) -> CertificateInfo:
        """Create a new certificate."""
        try:
            certificate_id = f"cert_{int(time.time())}"
            
            # In a real implementation, would generate actual certificate
            cert_info = CertificateInfo(
                certificate_id=certificate_id,
                common_name=common_name,
                certificate_type=certificate_type,
                status=CertificateStatus.VALID,
                issued_date=datetime.now(timezone.utc),
                expiry_date=datetime.now(timezone.utc) + timedelta(days=validity_days),
                issuer="PlexiChat CA",
                subject=f"CN={common_name}",
                serial_number=str(int(time.time())),
                fingerprint=f"sha256:{certificate_id}",
                key_size=key_size,
                san_list=san_list or [],
                certificate_path=f"{self.certificate_store_path}/{certificate_id}.crt",
                private_key_path=f"{self.certificate_store_path}/{certificate_id}.key"
            )
            
            self.certificates[certificate_id] = cert_info
            
            logger.info(f"Created certificate {certificate_id} for {common_name}")
            return cert_info
            
        except Exception as e:
            logger.error(f"Failed to create certificate: {e}")
            raise
    
    async def get_certificate(self, certificate_id: str) -> Optional[CertificateInfo]:
        """Get certificate information by ID."""
        return self.certificates.get(certificate_id)
    
    async def list_certificates(self, certificate_type: Optional[CertificateType] = None) -> List[CertificateInfo]:
        """List certificates, optionally filtered by type."""
        certificates = list(self.certificates.values())
        
        if certificate_type:
            certificates = [cert for cert in certificates if cert.certificate_type == certificate_type]
        
        return certificates
    
    async def revoke_certificate(self, certificate_id: str, reason: str = "unspecified") -> bool:
        """Revoke a certificate."""
        try:
            if certificate_id not in self.certificates:
                logger.warning(f"Certificate {certificate_id} not found")
                return False
            
            cert_info = self.certificates[certificate_id]
            cert_info.status = CertificateStatus.REVOKED
            cert_info.metadata["revocation_reason"] = reason
            cert_info.metadata["revocation_date"] = datetime.now(timezone.utc).isoformat()
            
            logger.info(f"Revoked certificate {certificate_id}: {reason}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke certificate {certificate_id}: {e}")
            return False
    
    async def renew_certificate(self, certificate_id: str) -> Optional[CertificateInfo]:
        """Renew a certificate."""
        try:
            if certificate_id not in self.certificates:
                logger.warning(f"Certificate {certificate_id} not found")
                return None
            
            old_cert = self.certificates[certificate_id]
            
            # Create new certificate with same parameters
            new_cert = await self.create_certificate(
                common_name=old_cert.common_name,
                certificate_type=old_cert.certificate_type,
                validity_days=365,
                key_size=old_cert.key_size,
                san_list=old_cert.san_list
            )
            
            # Mark old certificate as expired
            old_cert.status = CertificateStatus.EXPIRED
            
            logger.info(f"Renewed certificate {certificate_id} -> {new_cert.certificate_id}")
            return new_cert
            
        except Exception as e:
            logger.error(f"Failed to renew certificate {certificate_id}: {e}")
            return None
    
    async def check_certificate_expiry(self) -> List[CertificateInfo]:
        """Check for certificates that are expiring soon."""
        expiring_certificates = []
        threshold_date = datetime.now(timezone.utc) + timedelta(days=self.renewal_threshold_days)
        
        for cert_info in self.certificates.values():
            if cert_info.status == CertificateStatus.VALID:
                if cert_info.expiry_date <= threshold_date:
                    cert_info.status = CertificateStatus.EXPIRING_SOON
                    expiring_certificates.append(cert_info)
                elif cert_info.expiry_date <= datetime.now(timezone.utc):
                    cert_info.status = CertificateStatus.EXPIRED
        
        return expiring_certificates
    
    async def _certificate_monitoring_loop(self):
        """Background task for certificate monitoring."""
        while True:
            try:
                await asyncio.sleep(3600)  # Check every hour
                
                expiring_certs = await self.check_certificate_expiry()
                
                if expiring_certs:
                    logger.warning(f"Found {len(expiring_certs)} certificates expiring soon")
                    
                    if self.auto_renewal_enabled:
                        for cert in expiring_certs:
                            await self.renew_certificate(cert.certificate_id)
                
            except Exception as e:
                logger.error(f"Error in certificate monitoring: {e}")
    
    def get_certificate_stats(self) -> Dict[str, Any]:
        """Get certificate statistics."""
        stats = {
            "total_certificates": len(self.certificates),
            "by_status": {},
            "by_type": {},
            "expiring_soon": 0
        }
        
        for cert in self.certificates.values():
            # Count by status
            status = cert.status.value
            stats["by_status"][status] = stats["by_status"].get(status, 0) + 1
            
            # Count by type
            cert_type = cert.certificate_type.value
            stats["by_type"][cert_type] = stats["by_type"].get(cert_type, 0) + 1
            
            # Count expiring soon
            if cert.status == CertificateStatus.EXPIRING_SOON:
                stats["expiring_soon"] += 1
        
        return stats
    
    async def validate_certificate_chain(self, certificate_id: str) -> bool:
        """Validate a certificate chain."""
        try:
            if certificate_id not in self.certificates:
                return False
            
            # In a real implementation, would validate the actual certificate chain
            cert_info = self.certificates[certificate_id]
            
            # Simple validation - check if not expired or revoked
            if cert_info.status in [CertificateStatus.EXPIRED, CertificateStatus.REVOKED]:
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to validate certificate chain {certificate_id}: {e}")
            return False
    
    async def export_certificate(self, certificate_id: str, format_type: str = "pem") -> Optional[str]:
        """Export a certificate in the specified format."""
        try:
            if certificate_id not in self.certificates:
                return None
            
            cert_info = self.certificates[certificate_id]
            
            # In a real implementation, would read and format the actual certificate
            if format_type.lower() == "pem":
                return f"-----BEGIN CERTIFICATE-----\n{cert_info.certificate_id}\n-----END CERTIFICATE-----"
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to export certificate {certificate_id}: {e}")
            return None
    
    async def cleanup(self):
        """Cleanup certificate manager resources."""
        try:
            # Cancel background tasks
            for task in self.background_tasks:
                task.cancel()
            
            await asyncio.gather(*self.background_tasks, return_exceptions=True)
            
            logger.info("Certificate manager cleanup completed")
            
        except Exception as e:
            logger.error(f"Error during certificate manager cleanup: {e}")


# Global certificate manager instance
_certificate_manager: Optional[CertificateManager] = None


def get_certificate_manager() -> CertificateManager:
    """Get the global certificate manager instance."""
    global _certificate_manager
    if _certificate_manager is None:
        _certificate_manager = CertificateManager()
    return _certificate_manager


async def initialize_certificate_manager(config: Optional[Dict[str, Any]] = None) -> CertificateManager:
    """Initialize and return the certificate manager."""
    manager = get_certificate_manager()
    if config:
        manager.config.update(config)
    await manager.initialize()
    return manager
