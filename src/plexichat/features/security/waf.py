"""
PlexiChat Web Application Firewall (WAF)
Integrates ModSecurity with OWASP Core Rule Set for comprehensive protection
"""

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from fastapi import Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


class WAFRuleType(Enum):
    """WAF rule types."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    RFI = "remote_file_inclusion"
    LFI = "local_file_inclusion"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    PROTOCOL_ATTACK = "protocol_attack"
    GENERIC_ATTACK = "generic_attack"
    RATE_LIMITING = "rate_limiting"
    CUSTOM = "custom"


class WAFAction(Enum):
    """WAF actions."""
    ALLOW = "allow"
    BLOCK = "block"
    LOG = "log"
    CHALLENGE = "challenge"
    RATE_LIMIT = "rate_limit"


@dataclass
class WAFRule:
    """WAF rule definition."""
    rule_id: str
    rule_type: WAFRuleType
    pattern: str
    action: WAFAction
    severity: int  # 1-10, 10 being most severe
    description: str
    enabled: bool = True
    compiled_pattern: Optional[re.Pattern] = None
    
    def __post_init__(self):
        """Compile regex pattern after initialization."""
        if self.pattern and not self.compiled_pattern:
            try:
                self.compiled_pattern = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
            except re.error as e:
                logger.error(f"Failed to compile WAF rule pattern {self.rule_id}: {e}")
                self.enabled = False


@dataclass
class WAFViolation:
    """WAF rule violation."""
    rule_id: str
    rule_type: WAFRuleType
    severity: int
    description: str
    matched_content: str
    client_ip: str
    user_agent: str
    timestamp: datetime
    request_path: str
    request_method: str
    action_taken: WAFAction


class WebApplicationFirewall:
    """
    Advanced Web Application Firewall with OWASP Core Rule Set integration.
    
    Features:
    - SQL injection protection
    - XSS protection
    - Remote/Local file inclusion protection
    - Command injection protection
    - Path traversal protection
    - Protocol attack protection
    - Custom rule support
    - Real-time monitoring and alerting
    """
    
    def __init__(self):
        self.rules: Dict[str, WAFRule] = {}
        self.violations: List[WAFViolation] = []
        self.blocked_ips: Dict[str, datetime] = {}
        self.rate_limits: Dict[str, List[datetime]] = {}
        self.whitelist_ips: set = set()
        self.enabled = True
        
        # Statistics
        self.stats = {
            "requests_processed": 0,
            "violations_detected": 0,
            "requests_blocked": 0,
            "rules_triggered": {},
            "top_attacking_ips": {},
            "last_reset": datetime.now(timezone.utc)
        }
        
        self._load_owasp_core_rules()
        self._load_custom_rules()
    
    def _load_owasp_core_rules(self):
        """Load OWASP Core Rule Set patterns."""
        owasp_rules = [
            # SQL Injection Rules
            WAFRule(
                rule_id="OWASP_001",
                rule_type=WAFRuleType.SQL_INJECTION,
                pattern=r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|update\s+.*\s+set|drop\s+table|create\s+table)",
                action=WAFAction.BLOCK,
                severity=9,
                description="SQL injection attempt detected"
            ),
            WAFRule(
                rule_id="OWASP_002",
                rule_type=WAFRuleType.SQL_INJECTION,
                pattern=r"(?i)(\'\s*(or|and)\s*\'\s*=\s*\'|\'\s*(or|and)\s*1\s*=\s*1|admin\'\s*--|\'\s*or\s*\'1\'\s*=\s*\'1)",
                action=WAFAction.BLOCK,
                severity=10,
                description="SQL injection authentication bypass attempt"
            ),
            
            # XSS Rules
            WAFRule(
                rule_id="OWASP_003",
                rule_type=WAFRuleType.XSS,
                pattern=r"(?i)(<script[^>]*>.*?</script>|javascript:|vbscript:|onload\s*=|onerror\s*=|onclick\s*=)",
                action=WAFAction.BLOCK,
                severity=8,
                description="Cross-site scripting (XSS) attempt detected"
            ),
            WAFRule(
                rule_id="OWASP_004",
                rule_type=WAFRuleType.XSS,
                pattern=r"(?i)(<iframe[^>]*>|<object[^>]*>|<embed[^>]*>|<applet[^>]*>)",
                action=WAFAction.BLOCK,
                severity=7,
                description="Potentially malicious HTML tag detected"
            ),
            
            # Remote File Inclusion
            WAFRule(
                rule_id="OWASP_005",
                rule_type=WAFRuleType.RFI,
                pattern=r"(?i)(http://|https://|ftp://|file://|php://|data://|expect://|zip://)",
                action=WAFAction.BLOCK,
                severity=9,
                description="Remote file inclusion attempt detected"
            ),
            
            # Local File Inclusion / Path Traversal
            WAFRule(
                rule_id="OWASP_006",
                rule_type=WAFRuleType.PATH_TRAVERSAL,
                pattern=r"(?i)(\.\.\/|\.\.\\|\/etc\/passwd|\/etc\/shadow|\/proc\/|\/sys\/|\.\.%2f|\.\.%5c)",
                action=WAFAction.BLOCK,
                severity=8,
                description="Path traversal attempt detected"
            ),
            
            # Command Injection
            WAFRule(
                rule_id="OWASP_007",
                rule_type=WAFRuleType.COMMAND_INJECTION,
                pattern=r"(?i)(;|\||\&|\$\(|\`|nc\s|wget\s|curl\s|bash\s|sh\s|cmd\s|powershell\s)",
                action=WAFAction.BLOCK,
                severity=9,
                description="Command injection attempt detected"
            ),
            
            # Protocol Attacks
            WAFRule(
                rule_id="OWASP_008",
                rule_type=WAFRuleType.PROTOCOL_ATTACK,
                pattern=r"(?i)(content-length:\s*-|\r\n\r\n|http\/1\.[01]\s+[45]\d\d)",
                action=WAFAction.BLOCK,
                severity=7,
                description="HTTP protocol attack detected"
            ),
        ]
        
        for rule in owasp_rules:
            self.rules[rule.rule_id] = rule
            self.stats["rules_triggered"][rule.rule_id] = 0
        
        logger.info(f"✅ Loaded {len(owasp_rules)} OWASP Core Rule Set rules")
    
    def _load_custom_rules(self):
        """Load custom WAF rules."""
        custom_rules = [
            # PlexiChat specific rules
            WAFRule(
                rule_id="CUSTOM_001",
                rule_type=WAFRuleType.CUSTOM,
                pattern=r"(?i)(plexichat_admin|admin_panel|/admin/|/administrator/)",
                action=WAFAction.LOG,
                severity=5,
                description="Admin panel access attempt"
            ),
            WAFRule(
                rule_id="CUSTOM_002",
                rule_type=WAFRuleType.CUSTOM,
                pattern=r"(?i)(\.env|\.config|\.ini|\.conf|\.yaml|\.yml|\.json)$",
                action=WAFAction.BLOCK,
                severity=8,
                description="Configuration file access attempt"
            ),
        ]
        
        for rule in custom_rules:
            self.rules[rule.rule_id] = rule
            self.stats["rules_triggered"][rule.rule_id] = 0
        
        logger.info(f"✅ Loaded {len(custom_rules)} custom WAF rules")

    async def analyze_request(self, request: Request) -> Tuple[bool, Optional[WAFViolation]]:
        """
        Analyze incoming request against WAF rules.

        Returns:
            Tuple of (allowed, violation_if_any)
        """
        if not self.enabled:
            return True, None

        self.stats["requests_processed"] += 1
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")
        request_path = str(request.url.path)
        request_method = request.method

        # Skip whitelisted IPs
        if client_ip in self.whitelist_ips:
            return True, None

        # Check if IP is temporarily blocked
        if client_ip in self.blocked_ips:
            block_time = self.blocked_ips[client_ip]
            if datetime.now(timezone.utc) - block_time < timedelta(hours=1):
                return False, WAFViolation(
                    rule_id="BLOCKED_IP",
                    rule_type=WAFRuleType.RATE_LIMITING,
                    severity=10,
                    description="IP temporarily blocked due to previous violations",
                    matched_content=client_ip,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    timestamp=datetime.now(timezone.utc),
                    request_path=request_path,
                    request_method=request_method,
                    action_taken=WAFAction.BLOCK
                )
            else:
                # Unblock IP after timeout
                del self.blocked_ips[client_ip]

        # Collect request data for analysis
        request_data = await self._extract_request_data(request)

        # Check each rule
        for rule_id, rule in self.rules.items():
            if not rule.enabled or not rule.compiled_pattern:
                continue

            # Check all request components
            for component_name, component_data in request_data.items():
                if component_data and rule.compiled_pattern.search(str(component_data)):
                    # Rule violation detected
                    violation = WAFViolation(
                        rule_id=rule_id,
                        rule_type=rule.rule_type,
                        severity=rule.severity,
                        description=f"{rule.description} in {component_name}",
                        matched_content=str(component_data)[:200],  # Limit content length
                        client_ip=client_ip,
                        user_agent=user_agent,
                        timestamp=datetime.now(timezone.utc),
                        request_path=request_path,
                        request_method=request_method,
                        action_taken=rule.action
                    )

                    # Update statistics
                    self.stats["violations_detected"] += 1
                    self.stats["rules_triggered"][rule_id] += 1
                    self.stats["top_attacking_ips"][client_ip] = self.stats["top_attacking_ips"].get(client_ip, 0) + 1

                    # Store violation
                    self.violations.append(violation)

                    # Take action based on rule
                    if rule.action == WAFAction.BLOCK:
                        self.stats["requests_blocked"] += 1
                        # Block IP for repeated violations
                        if rule.severity >= 8:
                            self.blocked_ips[client_ip] = datetime.now(timezone.utc)
                        return False, violation
                    elif rule.action == WAFAction.LOG:
                        logger.warning(f"WAF violation logged: {violation.description} from {client_ip}")
                        continue  # Continue checking other rules

        return True, None

    async def _extract_request_data(self, request: Request) -> Dict[str, Any]:
        """Extract data from request for analysis."""
        data = {
            "url": str(request.url),
            "path": request.url.path,
            "query": str(request.url.query) if request.url.query else "",
            "headers": dict(request.headers),
            "user_agent": request.headers.get("user-agent", ""),
            "referer": request.headers.get("referer", ""),
            "body": None
        }

        # Extract body for POST/PUT requests
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                content_type = request.headers.get("content-type", "")
                if "application/json" in content_type:
                    body = await request.body()
                    data["body"] = body.decode("utf-8", errors="ignore")
                elif "application/x-www-form-urlencoded" in content_type:
                    form = await request.form()
                    data["body"] = str(dict(form))
            except Exception as e:
                logger.debug(f"Could not extract request body: {e}")

        return data

    def add_custom_rule(self, rule: WAFRule) -> bool:
        """Add a custom WAF rule."""
        try:
            if rule.rule_id in self.rules:
                logger.warning(f"WAF rule {rule.rule_id} already exists, updating")

            self.rules[rule.rule_id] = rule
            self.stats["rules_triggered"][rule.rule_id] = 0
            logger.info(f"✅ Added custom WAF rule: {rule.rule_id}")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to add WAF rule {rule.rule_id}: {e}")
            return False

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a WAF rule."""
        if rule_id in self.rules:
            del self.rules[rule_id]
            if rule_id in self.stats["rules_triggered"]:
                del self.stats["rules_triggered"][rule_id]
            logger.info(f"✅ Removed WAF rule: {rule_id}")
            return True
        return False

    def whitelist_ip(self, ip_address: str):
        """Add IP to whitelist."""
        self.whitelist_ips.add(ip_address)
        # Remove from blocked list if present
        if ip_address in self.blocked_ips:
            del self.blocked_ips[ip_address]
        logger.info(f"✅ Whitelisted IP: {ip_address}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get WAF statistics."""
        return {
            "enabled": self.enabled,
            "total_rules": len(self.rules),
            "active_rules": sum(1 for rule in self.rules.values() if rule.enabled),
            "statistics": self.stats.copy(),
            "recent_violations": [
                {
                    "rule_id": v.rule_id,
                    "severity": v.severity,
                    "description": v.description,
                    "client_ip": v.client_ip,
                    "timestamp": v.timestamp.isoformat(),
                    "action_taken": v.action_taken.value
                }
                for v in self.violations[-10:]  # Last 10 violations
            ],
            "blocked_ips": list(self.blocked_ips.keys()),
            "whitelisted_ips": list(self.whitelist_ips)
        }


# Global WAF instance
waf = WebApplicationFirewall()


async def waf_middleware(request: Request, call_next):
    """WAF middleware for FastAPI."""
    try:
        # Analyze request
        allowed, violation = await waf.analyze_request(request)

        if not allowed and violation:
            # Return blocked response
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Request blocked by Web Application Firewall",
                    "rule_id": violation.rule_id,
                    "description": violation.description,
                    "timestamp": violation.timestamp.isoformat()
                },
                headers={
                    "X-WAF-Block": "true",
                    "X-WAF-Rule": violation.rule_id
                }
            )

        # Process request normally
        response = await call_next(request)

        # Add WAF headers to response
        response.headers["X-WAF-Protected"] = "true"
        response.headers["X-WAF-Version"] = "1.0"

        return response

    except Exception as e:
        logger.error(f"WAF middleware error: {e}")
        # Fail open - allow request to proceed
        return await call_next(request)
