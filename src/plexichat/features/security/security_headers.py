import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

"""
PlexiChat Advanced Security Headers
Implements comprehensive security headers for maximum protection
"""

logger = logging.getLogger(__name__)


class SecurityHeaderType(Enum):
    """Security header types."""
    HSTS = "strict-transport-security"
    CSP = "content-security-policy"
    CSP_REPORT_ONLY = "content-security-policy-report-only"
    X_FRAME_OPTIONS = "x-frame-options"
    X_CONTENT_TYPE_OPTIONS = "x-content-type-options"
    X_XSS_PROTECTION = "x-xss-protection"
    REFERRER_POLICY = "referrer-policy"
    PERMISSIONS_POLICY = "permissions-policy"
    FEATURE_POLICY = "feature-policy"  # Legacy, replaced by Permissions-Policy
    CROSS_ORIGIN_EMBEDDER_POLICY = "cross-origin-embedder-policy"
    CROSS_ORIGIN_OPENER_POLICY = "cross-origin-opener-policy"
    CROSS_ORIGIN_RESOURCE_POLICY = "cross-origin-resource-policy"
    EXPECT_CT = "expect-ct"
    PUBLIC_KEY_PINS = "public-key-pins"
    CACHE_CONTROL = "cache-control"
    PRAGMA = "pragma"
    EXPIRES = "expires"
    SERVER = "server"
    X_POWERED_BY = "x-powered-by"
    X_SECURITY_LEVEL = "x-security-level"


@dataclass
class SecurityHeaderConfig:
    """Security header configuration."""
    header_type: SecurityHeaderType
    value: str
    enabled: bool = True
    description: str = ""
    security_level: str = "standard"  # minimal, standard, strict, paranoid


class AdvancedSecurityHeaders:
    """
    Advanced Security Headers Manager.
    
    Features:
    - Comprehensive security header suite
    - Multiple security levels (minimal, standard, strict, paranoid)
    - Dynamic header generation based on context
    - HSTS preload support
    - Certificate Transparency monitoring
    - Custom header support
    - Header validation and testing
    """
    
    def __init__(self):
        self.headers: Dict[str, SecurityHeaderConfig] = {}
        self.security_level = "standard"
        self.custom_headers: Dict[str, str] = {}
        
        self._initialize_default_headers()
    
    def _initialize_default_headers(self):
        """Initialize default security headers for different security levels."""
        
        # HTTP Strict Transport Security (HSTS)
        self.headers["hsts_standard"] = SecurityHeaderConfig(
            header_type=SecurityHeaderType.HSTS,
            value="max-age=31536000; includeSubDomains",
            security_level="standard",
            description="Enforce HTTPS for 1 year including subdomains"
        )
        
        self.headers["hsts_strict"] = SecurityHeaderConfig(
            header_type=SecurityHeaderType.HSTS,
            value="max-age=63072000; includeSubDomains; preload",
            security_level="strict",
            description="Enforce HTTPS for 2 years with preload"
        )
        
        # X-Frame-Options
        self.headers["x_frame_options"] = SecurityHeaderConfig(
            header_type=SecurityHeaderType.X_FRAME_OPTIONS,
            value="DENY",
            description="Prevent clickjacking attacks"
        )
        
        # X-Content-Type-Options
        self.headers["x_content_type_options"] = SecurityHeaderConfig(
            header_type=SecurityHeaderType.X_CONTENT_TYPE_OPTIONS,
            value="nosniff",
            description="Prevent MIME type sniffing"
        )
        
        # X-XSS-Protection (legacy but still useful)
        self.headers["x_xss_protection"] = SecurityHeaderConfig(
            header_type=SecurityHeaderType.X_XSS_PROTECTION,
            value="1; mode=block",
            description="Enable XSS filtering"
        )
        
        # Referrer Policy
        self.headers["referrer_policy_standard"] = SecurityHeaderConfig(
            header_type=SecurityHeaderType.REFERRER_POLICY,
            value="strict-origin-when-cross-origin",
            security_level="standard",
            description="Control referrer information"
        )
        
        self.headers["referrer_policy_strict"] = SecurityHeaderConfig(
            header_type=SecurityHeaderType.REFERRER_POLICY,
            value="no-referrer",
            security_level="strict",
            description="No referrer information sent"
        )
        
        # Permissions Policy (modern replacement for Feature Policy)
        self.headers["permissions_policy_standard"] = SecurityHeaderConfig(
            header_type=SecurityHeaderType.PERMISSIONS_POLICY,
            value=(
                "geolocation=(), microphone=(), camera=(), "
                "payment=(), usb=(), magnetometer=(), gyroscope=(), "
                "accelerometer=(), ambient-light-sensor=(), autoplay=(), "
                "encrypted-media=(), fullscreen=(), picture-in-picture=()"
            ),
            security_level="standard",
            description="Control browser features"
        )
        
        self.headers["permissions_policy_strict"] = SecurityHeaderConfig(
            header_type=SecurityHeaderType.PERMISSIONS_POLICY,
            value=(
                "geolocation=(), microphone=(), camera=(), "
                "payment=(), usb=(), magnetometer=(), gyroscope=(), "
                "accelerometer=(), ambient-light-sensor=(), autoplay=(), "
                "encrypted-media=(), fullscreen=(), picture-in-picture=(), "
                "midi=(), notifications=(), push=(), sync-xhr=(), "
                "wake-lock=(), screen-wake-lock=(), web-share=()"
            ),
            security_level="strict",
            description="Strict control of browser features"
        )
        
        # Cross-Origin Policies
        self.headers["cross_origin_embedder_policy"] = SecurityHeaderConfig(
            header_type=SecurityHeaderType.CROSS_ORIGIN_EMBEDDER_POLICY,
            value="require-corp",
            description="Require CORP for cross-origin resources"
        )
        
        self.headers["cross_origin_opener_policy"] = SecurityHeaderConfig(
            header_type=SecurityHeaderType.CROSS_ORIGIN_OPENER_POLICY,
            value="same-origin",
            description="Isolate browsing context"
        )
        
        self.headers["cross_origin_resource_policy"] = SecurityHeaderConfig(
            header_type=SecurityHeaderType.CROSS_ORIGIN_RESOURCE_POLICY,
            value="same-origin",
            description="Control cross-origin resource access"
        )
        
        # Cache Control for sensitive pages
        self.headers["cache_control_secure"] = SecurityHeaderConfig(
            header_type=SecurityHeaderType.CACHE_CONTROL,
            value="no-store, no-cache, must-revalidate, private",
            description="Prevent caching of sensitive content"
        )
        
        self.headers["pragma"] = SecurityHeaderConfig(
            header_type=SecurityHeaderType.PRAGMA,
            value="no-cache",
            description="Legacy cache control"
        )
        
        self.headers["expires"] = SecurityHeaderConfig(
            header_type=SecurityHeaderType.EXPIRES,
            value="0",
            description="Immediate expiration"
        )
        
        # Server identification
        self.headers["server"] = SecurityHeaderConfig(
            header_type=SecurityHeaderType.SERVER,
            value="PlexiChat/1.0",
            description="Minimal server identification"
        )
        
        # Custom PlexiChat security level indicator
        self.headers["x_security_level"] = SecurityHeaderConfig(
            header_type=SecurityHeaderType.X_SECURITY_LEVEL,
            value="Government-Grade",
            description="PlexiChat security level indicator"
        )
        
        # Expect-CT for Certificate Transparency
        self.headers["expect_ct"] = SecurityHeaderConfig(
            header_type=SecurityHeaderType.EXPECT_CT,
            value="max-age=86400, enforce, report-uri=\"/api/v1/security/ct-report\"",
            security_level="strict",
            description="Certificate Transparency enforcement"
        )
        
        logger.info(f" Initialized {len(self.headers)} security headers")
    
    def set_security_level(self, level: str):
        """Set the security level (minimal, standard, strict, paranoid)."""
        if level not in ["minimal", "standard", "strict", "paranoid"]:
            raise ValueError(f"Invalid security level: {level}")
        
        self.security_level = level
        logger.info(f" Security level set to: {level}")
    
    def get_headers_for_response(self, 
                                path: str = "/", 
                                is_secure_page: bool = False,
                                custom_csp: Optional[str] = None) -> Dict[str, str]:
        """Get security headers for a specific response."""
        headers = {}
        
        # Always include basic security headers
        headers[SecurityHeaderType.X_FRAME_OPTIONS.value] = self.headers["x_frame_options"].value
        headers[SecurityHeaderType.X_CONTENT_TYPE_OPTIONS.value] = self.headers["x_content_type_options"].value
        headers[SecurityHeaderType.X_XSS_PROTECTION.value] = self.headers["x_xss_protection"].value
        headers[SecurityHeaderType.SERVER.value] = self.headers["server"].value
        headers[SecurityHeaderType.X_SECURITY_LEVEL.value] = self.headers["x_security_level"].value
        
        # HSTS based on security level
        if self.security_level in ["standard", "strict", "paranoid"]:
            hsts_key = "hsts_strict" if self.security_level in ["strict", "paranoid"] else "hsts_standard"
            headers[SecurityHeaderType.HSTS.value] = self.headers[hsts_key].value
        
        # Referrer Policy based on security level
        if self.security_level in ["minimal", "standard"]:
            headers[SecurityHeaderType.REFERRER_POLICY.value] = self.headers["referrer_policy_standard"].value
        else:
            headers[SecurityHeaderType.REFERRER_POLICY.value] = self.headers["referrer_policy_strict"].value
        
        # Permissions Policy based on security level
        if self.security_level in ["strict", "paranoid"]:
            headers[SecurityHeaderType.PERMISSIONS_POLICY.value] = self.headers["permissions_policy_strict"].value
        else:
            headers[SecurityHeaderType.PERMISSIONS_POLICY.value] = self.headers["permissions_policy_standard"].value
        
        # Cross-Origin policies for strict security
        if self.security_level in ["strict", "paranoid"]:
            headers[SecurityHeaderType.CROSS_ORIGIN_EMBEDDER_POLICY.value] = self.headers["cross_origin_embedder_policy"].value
            headers[SecurityHeaderType.CROSS_ORIGIN_OPENER_POLICY.value] = self.headers["cross_origin_opener_policy"].value
            headers[SecurityHeaderType.CROSS_ORIGIN_RESOURCE_POLICY.value] = self.headers["cross_origin_resource_policy"].value
        
        # Expect-CT for strict security
        if self.security_level in ["strict", "paranoid"]:
            headers[SecurityHeaderType.EXPECT_CT.value] = self.headers["expect_ct"].value
        
        # Cache control for secure pages
        if is_secure_page or path.startswith("/admin") or path.startswith("/api/v1/auth"):
            headers[SecurityHeaderType.CACHE_CONTROL.value] = self.headers["cache_control_secure"].value
            headers[SecurityHeaderType.PRAGMA.value] = self.headers["pragma"].value
            headers[SecurityHeaderType.EXPIRES.value] = self.headers["expires"].value
        
        # Add custom CSP if provided
        if custom_csp:
            headers[SecurityHeaderType.CSP.value] = custom_csp
        
        # Add custom headers
        headers.update(self.custom_headers)
        
        # Remove X-Powered-By if present (security through obscurity)
        headers[SecurityHeaderType.X_POWERED_BY.value] = ""
        
        return headers
    
    def add_custom_header(self, name: str, value: str):
        """Add a custom security header."""
        self.custom_headers[name.lower()] = value
        logger.info(f" Added custom header: {name}")
    
    def remove_custom_header(self, name: str):
        """Remove a custom security header."""
        if name.lower() in self.custom_headers:
            del self.custom_headers[name.lower()]
            logger.info(f" Removed custom header: {name}")
    
    def validate_headers(self, headers: Dict[str, str]) -> Dict[str, List[str]]:
        """Validate security headers and return recommendations."""
        issues = {
            "missing": [],
            "weak": [],
            "recommendations": []
        }
        
        # Check for essential headers
        essential_headers = [
            SecurityHeaderType.HSTS.value,
            SecurityHeaderType.X_FRAME_OPTIONS.value,
            SecurityHeaderType.X_CONTENT_TYPE_OPTIONS.value,
            SecurityHeaderType.CSP.value
        ]
        
        for header in essential_headers:
            if header not in headers:
                issues["missing"].append(f"Missing essential header: {header}")
        
        # Check HSTS configuration
        if SecurityHeaderType.HSTS.value in headers:
            hsts_value = headers[SecurityHeaderType.HSTS.value]
            if "max-age" not in hsts_value:
                issues["weak"].append("HSTS missing max-age directive")
            elif "max-age=31536000" not in hsts_value:
                issues["recommendations"].append("Consider increasing HSTS max-age to 1 year")
            
            if "includeSubDomains" not in hsts_value:
                issues["recommendations"].append("Consider adding includeSubDomains to HSTS")
            
            if "preload" not in hsts_value and self.security_level in ["strict", "paranoid"]:
                issues["recommendations"].append("Consider adding preload to HSTS for maximum security")
        
        return issues
    
    def get_security_score(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Calculate a security score based on implemented headers."""
        score = 0
        max_score = 100
        details = {}
        
        # Essential headers (40 points)
        essential_checks = {
            SecurityHeaderType.HSTS.value: 15,
            SecurityHeaderType.CSP.value: 15,
            SecurityHeaderType.X_FRAME_OPTIONS.value: 5,
            SecurityHeaderType.X_CONTENT_TYPE_OPTIONS.value: 5
        }
        
        for header, points in essential_checks.items():
            if header in headers:
                score += points
                details[header] = " Present"
            else:
                details[header] = " Missing"
        
        # Additional security headers (60 points)
        additional_checks = {
            SecurityHeaderType.REFERRER_POLICY.value: 10,
            SecurityHeaderType.PERMISSIONS_POLICY.value: 15,
            SecurityHeaderType.CROSS_ORIGIN_EMBEDDER_POLICY.value: 10,
            SecurityHeaderType.CROSS_ORIGIN_OPENER_POLICY.value: 10,
            SecurityHeaderType.CROSS_ORIGIN_RESOURCE_POLICY.value: 10,
            SecurityHeaderType.EXPECT_CT.value: 5
        }
        
        for header, points in additional_checks.items():
            if header in headers:
                score += points
                details[header] = " Present"
            else:
                details[header] = " Optional but recommended"
        
        # Calculate grade
        if score >= 90:
            grade = "A+"
        elif score >= 80:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 60:
            grade = "C"
        else:
            grade = "F"
        
        return {
            "score": score,
            "max_score": max_score,
            "percentage": round((score / max_score) * 100, 1),
            "grade": grade,
            "details": details
        }


# Global security headers manager instance
security_headers_manager = AdvancedSecurityHeaders()
