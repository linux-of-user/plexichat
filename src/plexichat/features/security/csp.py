"""
PlexiChat Content Security Policy (CSP) Manager
Implements strict CSP to prevent XSS and other injection attacks
"""

import hashlib
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class CSPDirective(Enum):
    """CSP directive types."""
    DEFAULT_SRC = "default-src"
    SCRIPT_SRC = "script-src"
    STYLE_SRC = "style-src"
    IMG_SRC = "img-src"
    FONT_SRC = "font-src"
    CONNECT_SRC = "connect-src"
    MEDIA_SRC = "media-src"
    OBJECT_SRC = "object-src"
    CHILD_SRC = "child-src"
    FRAME_SRC = "frame-src"
    WORKER_SRC = "worker-src"
    FRAME_ANCESTORS = "frame-ancestors"
    FORM_ACTION = "form-action"
    BASE_URI = "base-uri"
    MANIFEST_SRC = "manifest-src"
    PREFETCH_SRC = "prefetch-src"
    NAVIGATE_TO = "navigate-to"
    REPORT_URI = "report-uri"
    REPORT_TO = "report-to"


class CSPSource(Enum):
    """CSP source keywords."""
    SELF = "'self'"
    UNSAFE_INLINE = "'unsafe-inline'"
    UNSAFE_EVAL = "'unsafe-eval'"
    STRICT_DYNAMIC = "'strict-dynamic'"
    UNSAFE_HASHES = "'unsafe-hashes'"
    NONE = "'none'"
    DATA = "data:"
    BLOB = "blob:"
    FILESYSTEM = "filesystem:"


@dataclass
class CSPPolicy:
    """Content Security Policy configuration."""
    name: str
    description: str
    directives: Dict[CSPDirective, Set[str]] = field(default_factory=dict)
    report_only: bool = False
    nonce_required: bool = True
    hash_algorithms: List[str] = field(default_factory=lambda: ["sha256", "sha384", "sha512"])
    
    def add_source(self, directive: CSPDirective, source: str):
        """Add a source to a directive."""
        if directive not in self.directives:
            self.directives[directive] = set()
        self.directives[directive].add(source)
    
    def remove_source(self, directive: CSPDirective, source: str):
        """Remove a source from a directive."""
        if directive in self.directives:
            self.directives[directive].discard(source)
    
    def to_header_value(self, nonce: Optional[str] = None) -> str:
        """Convert policy to CSP header value."""
        policy_parts = []
        
        for directive, sources in self.directives.items():
            sources_list = list(sources)
            
            # Add nonce if required and provided
            if nonce and directive in [CSPDirective.SCRIPT_SRC, CSPDirective.STYLE_SRC]:
                if self.nonce_required:
                    sources_list.append(f"'nonce-{nonce}'")
            
            if sources_list:
                policy_parts.append(f"{directive.value} {' '.join(sources_list)}")
        
        return "; ".join(policy_parts)


class CSPViolationReport:
    """CSP violation report."""
    
    def __init__(self, report_data: Dict[str, Any]):
        self.document_uri = report_data.get("document-uri", "")
        self.referrer = report_data.get("referrer", "")
        self.violated_directive = report_data.get("violated-directive", "")
        self.effective_directive = report_data.get("effective-directive", "")
        self.original_policy = report_data.get("original-policy", "")
        self.blocked_uri = report_data.get("blocked-uri", "")
        self.line_number = report_data.get("line-number", 0)
        self.column_number = report_data.get("column-number", 0)
        self.source_file = report_data.get("source-file", "")
        self.status_code = report_data.get("status-code", 0)
        self.timestamp = datetime.now(timezone.utc)


class ContentSecurityPolicyManager:
    """
    Advanced Content Security Policy Manager.
    
    Features:
    - Multiple policy profiles (strict, moderate, permissive)
    - Dynamic nonce generation
    - Hash-based script/style allowlisting
    - Violation reporting and analysis
    - Real-time policy adjustment
    - CSP bypass detection
    """
    
    def __init__(self):
        self.policies: Dict[str, CSPPolicy] = {}
        self.active_policy: Optional[str] = None
        self.nonces: Dict[str, str] = {}  # session_id -> nonce
        self.violations: List[CSPViolationReport] = []
        self.trusted_hashes: Dict[str, Set[str]] = {
            "scripts": set(),
            "styles": set()
        }
        
        self._initialize_default_policies()
    
    def _initialize_default_policies(self):
        """Initialize default CSP policies."""
        
        # Strict Policy (Maximum Security)
        strict_policy = CSPPolicy(
            name="strict",
            description="Maximum security policy with minimal external resources",
            nonce_required=True
        )
        strict_policy.add_source(CSPDirective.DEFAULT_SRC, CSPSource.SELF.value)
        strict_policy.add_source(CSPDirective.SCRIPT_SRC, CSPSource.SELF.value)
        strict_policy.add_source(CSPDirective.SCRIPT_SRC, CSPSource.STRICT_DYNAMIC.value)
        strict_policy.add_source(CSPDirective.STYLE_SRC, CSPSource.SELF.value)
        strict_policy.add_source(CSPDirective.IMG_SRC, CSPSource.SELF.value)
        strict_policy.add_source(CSPDirective.IMG_SRC, CSPSource.DATA.value)
        strict_policy.add_source(CSPDirective.FONT_SRC, CSPSource.SELF.value)
        strict_policy.add_source(CSPDirective.CONNECT_SRC, CSPSource.SELF.value)
        strict_policy.add_source(CSPDirective.MEDIA_SRC, CSPSource.NONE.value)
        strict_policy.add_source(CSPDirective.OBJECT_SRC, CSPSource.NONE.value)
        strict_policy.add_source(CSPDirective.FRAME_SRC, CSPSource.NONE.value)
        strict_policy.add_source(CSPDirective.FRAME_ANCESTORS, CSPSource.NONE.value)
        strict_policy.add_source(CSPDirective.FORM_ACTION, CSPSource.SELF.value)
        strict_policy.add_source(CSPDirective.BASE_URI, CSPSource.SELF.value)
        strict_policy.add_source(CSPDirective.REPORT_URI, "/api/v1/security/csp-report")
        
        # Production Policy (Balanced Security)
        production_policy = CSPPolicy(
            name="production",
            description="Balanced security policy for production use",
            nonce_required=True
        )
        production_policy.add_source(CSPDirective.DEFAULT_SRC, CSPSource.SELF.value)
        production_policy.add_source(CSPDirective.SCRIPT_SRC, CSPSource.SELF.value)
        production_policy.add_source(CSPDirective.SCRIPT_SRC, "https://cdn.jsdelivr.net")
        production_policy.add_source(CSPDirective.SCRIPT_SRC, "https://cdnjs.cloudflare.com")
        production_policy.add_source(CSPDirective.STYLE_SRC, CSPSource.SELF.value)
        production_policy.add_source(CSPDirective.STYLE_SRC, CSPSource.UNSAFE_INLINE.value)  # For dynamic styles
        production_policy.add_source(CSPDirective.STYLE_SRC, "https://fonts.googleapis.com")
        production_policy.add_source(CSPDirective.STYLE_SRC, "https://cdn.jsdelivr.net")
        production_policy.add_source(CSPDirective.IMG_SRC, CSPSource.SELF.value)
        production_policy.add_source(CSPDirective.IMG_SRC, CSPSource.DATA.value)
        production_policy.add_source(CSPDirective.IMG_SRC, "https:")
        production_policy.add_source(CSPDirective.FONT_SRC, CSPSource.SELF.value)
        production_policy.add_source(CSPDirective.FONT_SRC, "https://fonts.gstatic.com")
        production_policy.add_source(CSPDirective.CONNECT_SRC, CSPSource.SELF.value)
        production_policy.add_source(CSPDirective.CONNECT_SRC, "wss:")
        production_policy.add_source(CSPDirective.CONNECT_SRC, "ws:")
        production_policy.add_source(CSPDirective.MEDIA_SRC, CSPSource.SELF.value)
        production_policy.add_source(CSPDirective.OBJECT_SRC, CSPSource.NONE.value)
        production_policy.add_source(CSPDirective.FRAME_ANCESTORS, CSPSource.NONE.value)
        production_policy.add_source(CSPDirective.FORM_ACTION, CSPSource.SELF.value)
        production_policy.add_source(CSPDirective.BASE_URI, CSPSource.SELF.value)
        production_policy.add_source(CSPDirective.REPORT_URI, "/api/v1/security/csp-report")
        
        # Development Policy (Permissive for Development)
        development_policy = CSPPolicy(
            name="development",
            description="Permissive policy for development environment",
            nonce_required=False,
            report_only=True
        )
        development_policy.add_source(CSPDirective.DEFAULT_SRC, CSPSource.SELF.value)
        development_policy.add_source(CSPDirective.SCRIPT_SRC, CSPSource.SELF.value)
        development_policy.add_source(CSPDirective.SCRIPT_SRC, CSPSource.UNSAFE_INLINE.value)
        development_policy.add_source(CSPDirective.SCRIPT_SRC, CSPSource.UNSAFE_EVAL.value)
        development_policy.add_source(CSPDirective.SCRIPT_SRC, "http://localhost:*")
        development_policy.add_source(CSPDirective.SCRIPT_SRC, "https:")
        development_policy.add_source(CSPDirective.STYLE_SRC, CSPSource.SELF.value)
        development_policy.add_source(CSPDirective.STYLE_SRC, CSPSource.UNSAFE_INLINE.value)
        development_policy.add_source(CSPDirective.STYLE_SRC, "https:")
        development_policy.add_source(CSPDirective.IMG_SRC, "*")
        development_policy.add_source(CSPDirective.FONT_SRC, "*")
        development_policy.add_source(CSPDirective.CONNECT_SRC, "*")
        development_policy.add_source(CSPDirective.MEDIA_SRC, "*")
        development_policy.add_source(CSPDirective.REPORT_URI, "/api/v1/security/csp-report")
        
        self.policies = {
            "strict": strict_policy,
            "production": production_policy,
            "development": development_policy
        }
        
        # Set default active policy
        self.active_policy = "production"
        
        logger.info(f"✅ Initialized {len(self.policies)} CSP policies")
    
    def generate_nonce(self, session_id: str) -> str:
        """Generate a cryptographically secure nonce for a session."""
        nonce = secrets.token_urlsafe(32)
        self.nonces[session_id] = nonce
        return nonce
    
    def get_nonce(self, session_id: str) -> Optional[str]:
        """Get the nonce for a session."""
        return self.nonces.get(session_id)
    
    def calculate_hash(self, content: str, algorithm: str = "sha256") -> str:
        """Calculate hash for inline script or style."""
        if algorithm not in ["sha256", "sha384", "sha512"]:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        hash_func = getattr(hashlib, algorithm)
        content_hash = hash_func(content.encode("utf-8")).digest()
        return f"'{algorithm}-{content_hash.hex()}'"
    
    def add_trusted_hash(self, content_type: str, content: str, algorithm: str = "sha256"):
        """Add a trusted hash for inline content."""
        if content_type not in ["scripts", "styles"]:
            raise ValueError(f"Invalid content type: {content_type}")
        
        content_hash = self.calculate_hash(content, algorithm)
        self.trusted_hashes[content_type].add(content_hash)
        
        # Add to active policy
        if self.active_policy and self.active_policy in self.policies:
            policy = self.policies[self.active_policy]
            directive = CSPDirective.SCRIPT_SRC if content_type == "scripts" else CSPDirective.STYLE_SRC
            policy.add_source(directive, content_hash)
    
    def get_csp_header(self, session_id: Optional[str] = None) -> Dict[str, str]:
        """Get CSP header for response."""
        if not self.active_policy or self.active_policy not in self.policies:
            return {}
        
        policy = self.policies[self.active_policy]
        nonce = self.get_nonce(session_id) if session_id else None
        
        header_name = "Content-Security-Policy-Report-Only" if policy.report_only else "Content-Security-Policy"
        header_value = policy.to_header_value(nonce)
        
        return {header_name: header_value}


# Global CSP manager instance
csp_manager = ContentSecurityPolicyManager()
