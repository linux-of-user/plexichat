import os
import ssl
import subprocess
from pathlib import Path
from typing import Optional, Tuple

class CertificateManager:
    """
    Handles SSL certificate management for NetLink.
    Supports self-signed and Let's Encrypt certificates.
    """
    def __init__(self, cert_dir: str = "config/certs"):
        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(parents=True, exist_ok=True)

    def get_cert_paths(self, domain: str) -> Tuple[Path, Path]:
        cert_file = self.cert_dir / f"{domain}.crt"
        key_file = self.cert_dir / f"{domain}.key"
        return cert_file, key_file

    def has_valid_cert(self, domain: str) -> bool:
        cert_file, key_file = self.get_cert_paths(domain)
        return cert_file.exists() and key_file.exists()

    def create_self_signed_cert(self, domain: str, overwrite: bool = False) -> Tuple[Path, Path]:
        cert_file, key_file = self.get_cert_paths(domain)
        if not overwrite and cert_file.exists() and key_file.exists():
            return cert_file, key_file
        # Use openssl to generate cert
        subprocess.check_call([
            "openssl", "req", "-x509", "-nodes", "-days", "365",
            "-newkey", "rsa:2048",
            "-keyout", str(key_file),
            "-out", str(cert_file),
            "-subj", f"/CN={domain}"
        ])
        return cert_file, key_file

    def request_lets_encrypt_cert(self, domain: str, email: str) -> Optional[Tuple[Path, Path]]:
        # This is a placeholder for Let's Encrypt integration (e.g., using certbot)
        # In production, use certbot or acme library
        print(f"[CertManager] Requesting Let's Encrypt cert for {domain} (not implemented)")
        return None

    def ensure_certificate(self, domain: str, email: Optional[str] = None, use_lets_encrypt: bool = False) -> Tuple[Path, Path]:
        if use_lets_encrypt and email:
            certs = self.request_lets_encrypt_cert(domain, email)
            if certs:
                return certs
        # Fallback to self-signed
        return self.create_self_signed_cert(domain) 