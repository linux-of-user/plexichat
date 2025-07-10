"""
MITM (Man-in-the-Middle) Attack Protection for PlexiChat
Comprehensive protection against various MITM attack vectors.
"""

import hashlib
import hmac
import secrets
import time
import base64
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from fastapi import Request, HTTPException
import ssl
import socket

from plexichat.app.logger_config import logger


class CertificatePinning:
    """Certificate pinning for enhanced security."""
    
    def __init__(self):
        self.pinned_certificates: Dict[str, List[str]] = {}
        self.pinned_public_keys: Dict[str, List[str]] = {}
        
    def add_certificate_pin(self, domain: str, cert_fingerprint: str):
        """Add certificate fingerprint for pinning."""
        if domain not in self.pinned_certificates:
            self.pinned_certificates[domain] = []
        self.pinned_certificates[domain].append(cert_fingerprint)
        
    def add_public_key_pin(self, domain: str, public_key_hash: str):
        """Add public key hash for pinning."""
        if domain not in self.pinned_public_keys:
            self.pinned_public_keys[domain] = []
        self.pinned_public_keys[domain].append(public_key_hash)
        
    def verify_certificate(self, domain: str, cert_der: bytes) -> bool:
        """Verify certificate against pinned values."""
        if domain not in self.pinned_certificates:
            return True  # No pinning configured
            
        # Calculate certificate fingerprint
        cert_hash = hashlib.sha256(cert_der).hexdigest()
        
        return cert_hash in self.pinned_certificates[domain]


class RequestIntegrityChecker:
    """Check request integrity to detect tampering."""
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key.encode()
        
    def generate_request_signature(self, method: str, path: str, body: bytes, timestamp: str) -> str:
        """Generate HMAC signature for request."""
        message = f"{method}|{path}|{timestamp}".encode() + body
        signature = hmac.new(self.secret_key, message, hashlib.sha256).hexdigest()
        return signature
        
    def verify_request_signature(self, method: str, path: str, body: bytes, 
                                timestamp: str, signature: str) -> bool:
        """Verify request signature."""
        expected_signature = self.generate_request_signature(method, path, body, timestamp)
        return hmac.compare_digest(expected_signature, signature)
        
    def is_timestamp_valid(self, timestamp: str, max_age_seconds: int = 300) -> bool:
        """Check if timestamp is within acceptable range."""
        try:
            request_time = datetime.fromisoformat(timestamp)
            current_time = datetime.utcnow()
            age = (current_time - request_time).total_seconds()
            return 0 <= age <= max_age_seconds
        except:
            return False


class ChannelBinding:
    """Implement channel binding to prevent session hijacking."""
    
    def __init__(self):
        self.channel_bindings: Dict[str, str] = {}
        
    def generate_channel_binding(self, tls_info: Dict[str, Any]) -> str:
        """Generate channel binding token from TLS information."""
        # Use TLS Finished message or certificate info
        binding_data = json.dumps(tls_info, sort_keys=True)
        return hashlib.sha256(binding_data.encode()).hexdigest()
        
    def store_channel_binding(self, session_id: str, binding: str):
        """Store channel binding for session."""
        self.channel_bindings[session_id] = binding
        
    def verify_channel_binding(self, session_id: str, current_binding: str) -> bool:
        """Verify channel binding matches stored value."""
        stored_binding = self.channel_bindings.get(session_id)
        if not stored_binding:
            return False
        return hmac.compare_digest(stored_binding, current_binding)


class AntiReplayProtection:
    """Protect against replay attacks."""
    
    def __init__(self, window_size: int = 300):
        self.window_size = window_size  # seconds
        self.used_nonces: Dict[str, datetime] = {}
        self.request_timestamps: Dict[str, datetime] = {}
        
    def generate_nonce(self) -> str:
        """Generate cryptographically secure nonce."""
        return secrets.token_urlsafe(32)
        
    def is_nonce_valid(self, nonce: str) -> bool:
        """Check if nonce hasn't been used before."""
        current_time = datetime.utcnow()
        
        # Clean old nonces
        self._cleanup_old_nonces(current_time)
        
        if nonce in self.used_nonces:
            return False
            
        self.used_nonces[nonce] = current_time
        return True
        
    def _cleanup_old_nonces(self, current_time: datetime):
        """Remove old nonces outside the time window."""
        cutoff_time = current_time - timedelta(seconds=self.window_size)
        expired_nonces = [
            nonce for nonce, timestamp in self.used_nonces.items()
            if timestamp < cutoff_time
        ]
        for nonce in expired_nonces:
            del self.used_nonces[nonce]


class TLSSecurityChecker:
    """Check TLS configuration and security."""
    
    def __init__(self):
        self.min_tls_version = ssl.TLSVersion.TLSv1_2
        self.allowed_ciphers = [
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES256-SHA384',
            'ECDHE-RSA-AES128-SHA256'
        ]
        
    def check_tls_security(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Check TLS security configuration."""
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    return {
                        "tls_version": version,
                        "cipher_suite": cipher[0] if cipher else None,
                        "certificate_der": cert,
                        "is_secure": self._evaluate_security(version, cipher)
                    }
                    
        except Exception as e:
            logger.error(f"TLS security check failed for {hostname}: {e}")
            return {"error": str(e), "is_secure": False}
            
    def _evaluate_security(self, version: str, cipher: Tuple) -> bool:
        """Evaluate if TLS configuration is secure."""
        if not version or version < "TLSv1.2":
            return False
            
        if cipher and cipher[0] not in self.allowed_ciphers:
            logger.warning(f"Weak cipher detected: {cipher[0]}")
            
        return True


class MITMProtectionSystem:
    """Comprehensive MITM protection system."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.secret_key = self.config.get('secret_key', secrets.token_urlsafe(32))
        
        # Initialize components
        self.cert_pinning = CertificatePinning()
        self.integrity_checker = RequestIntegrityChecker(self.secret_key)
        self.channel_binding = ChannelBinding()
        self.replay_protection = AntiReplayProtection()
        self.tls_checker = TLSSecurityChecker()
        
        # Security headers
        self.security_headers = {
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
        }
        
        logger.info("MITM protection system initialized")
        
    def validate_request(self, request: Request) -> Dict[str, Any]:
        """Comprehensive request validation."""
        validation_results = {
            "valid": True,
            "issues": [],
            "security_score": 100
        }
        
        # Check for required security headers
        self._check_security_headers(request, validation_results)
        
        # Validate request signature if present
        self._validate_request_signature(request, validation_results)
        
        # Check for replay attacks
        self._check_replay_protection(request, validation_results)
        
        # Validate TLS information
        self._validate_tls_info(request, validation_results)
        
        return validation_results
        
    def _check_security_headers(self, request: Request, results: Dict[str, Any]):
        """Check for security headers."""
        required_headers = ['User-Agent', 'Accept']
        
        for header in required_headers:
            if header not in request.headers:
                results["issues"].append(f"Missing required header: {header}")
                results["security_score"] -= 10
                
        # Check for suspicious headers
        suspicious_patterns = ['curl', 'wget', 'python-requests']
        user_agent = request.headers.get('User-Agent', '').lower()
        
        if any(pattern in user_agent for pattern in suspicious_patterns):
            results["issues"].append("Suspicious User-Agent detected")
            results["security_score"] -= 20
            
    def _validate_request_signature(self, request: Request, results: Dict[str, Any]):
        """Validate request signature if present."""
        signature = request.headers.get('X-Request-Signature')
        timestamp = request.headers.get('X-Request-Timestamp')
        
        if signature and timestamp:
            # Get request body (this would need to be handled properly in middleware)
            body = b''  # Placeholder
            
            if not self.integrity_checker.is_timestamp_valid(timestamp):
                results["issues"].append("Invalid or expired timestamp")
                results["security_score"] -= 30
                results["valid"] = False
                
            if not self.integrity_checker.verify_request_signature(
                request.method, str(request.url.path), body, timestamp, signature
            ):
                results["issues"].append("Invalid request signature")
                results["security_score"] -= 50
                results["valid"] = False
                
    def _check_replay_protection(self, request: Request, results: Dict[str, Any]):
        """Check for replay attacks."""
        nonce = request.headers.get('X-Request-Nonce')
        
        if nonce:
            if not self.replay_protection.is_nonce_valid(nonce):
                results["issues"].append("Replay attack detected (duplicate nonce)")
                results["security_score"] -= 40
                results["valid"] = False
                
    def _validate_tls_info(self, request: Request, results: Dict[str, Any]):
        """Validate TLS information."""
        # Check if request is over HTTPS
        if request.url.scheme != 'https':
            results["issues"].append("Request not over HTTPS")
            results["security_score"] -= 30
            
        # Additional TLS validation would be done here
        
    def generate_security_token(self, user_id: int, session_id: str) -> str:
        """Generate security token for client."""
        timestamp = datetime.utcnow().isoformat()
        nonce = self.replay_protection.generate_nonce()
        
        token_data = {
            "user_id": user_id,
            "session_id": session_id,
            "timestamp": timestamp,
            "nonce": nonce
        }
        
        token_json = json.dumps(token_data, sort_keys=True)
        signature = hmac.new(
            self.secret_key.encode(),
            token_json.encode(),
            hashlib.sha256
        ).hexdigest()
        
        token_data["signature"] = signature
        
        return base64.b64encode(json.dumps(token_data).encode()).decode()
        
    def verify_security_token(self, token: str) -> Dict[str, Any]:
        """Verify security token."""
        try:
            token_data = json.loads(base64.b64decode(token).decode())
            signature = token_data.pop("signature")
            
            # Verify signature
            token_json = json.dumps(token_data, sort_keys=True)
            expected_signature = hmac.new(
                self.secret_key.encode(),
                token_json.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_signature):
                return {"valid": False, "error": "Invalid signature"}
                
            # Check timestamp
            if not self.integrity_checker.is_timestamp_valid(token_data["timestamp"]):
                return {"valid": False, "error": "Token expired"}
                
            # Check nonce
            if not self.replay_protection.is_nonce_valid(token_data["nonce"]):
                return {"valid": False, "error": "Token already used"}
                
            return {"valid": True, "data": token_data}
            
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return {"valid": False, "error": "Invalid token format"}
            
    def get_security_headers(self) -> Dict[str, str]:
        """Get security headers to add to responses."""
        return self.security_headers.copy()


# Global MITM protection instance
mitm_protection = MITMProtectionSystem()


def mitm_protection_middleware(request: Request, call_next):
    """Middleware for MITM protection."""
    # Validate request
    validation = mitm_protection.validate_request(request)
    
    if not validation["valid"]:
        logger.warning(f"MITM protection blocked request: {validation['issues']}")
        raise HTTPException(
            status_code=403,
            detail="Request blocked by security system"
        )
    
    # Process request
    response = call_next(request)
    
    # Add security headers
    for header, value in mitm_protection.get_security_headers().items():
        response.headers[header] = value
        
    return response
