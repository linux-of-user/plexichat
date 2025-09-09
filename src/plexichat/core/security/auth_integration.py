"""
Authentication Integration for PlexiChat Security Module
Integrates authentication services with security features.

Features:
- Brute force protection integration
- Device tracking and trust management
- Session security validation
- Risk assessment integration
- Authentication event monitoring
"""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

from plexichat.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class AuthSecurityMetrics:
    """Authentication security metrics."""

    total_auth_attempts: int = 0
    successful_auths: int = 0
    failed_auths: int = 0
    brute_force_blocks: int = 0
    device_trust_grants: int = 0
    risk_assessments: int = 0
    high_risk_auths: int = 0


class AuthSecurityIntegration:
    """
    Authentication security integration system.

    Features:
    - Brute force protection with progressive delays
    - Device tracking and trust management
    - Session security validation
    - Risk assessment for authentication attempts
    - Integration with authentication services
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("brute_force_protection", True)

        if not self.enabled:
            logger.info("Authentication security integration is disabled")
            return

        # Brute force protection settings
        self.max_attempts = 5
        self.lockout_duration_minutes = 30
        self.progressive_delays = [0, 1, 5, 15, 60]  # seconds

        # Device tracking
        self.device_tracking_enabled = config.get("device_tracking", True)
        self.known_devices: Dict[str, Dict[str, Any]] = {}
        self.trusted_devices: Set[str] = set()

        # Risk assessment
        self.risk_assessment_enabled = config.get("risk_assessment", True)
        self.risk_thresholds = {"low": 30, "medium": 50, "high": 70, "critical": 90}

        # Session security
        self.session_timeout_seconds = config.get("session_timeout", 3600)

        # Metrics
        self.metrics = AuthSecurityMetrics()

        # Brute force tracking
        self.brute_force_tracking: Dict[str, Dict[str, Any]] = {}

        logger.info("Authentication security integration initialized")

    async def validate_auth_security(self, context: Any) -> Dict[str, Any]:
        """
        Validate authentication security for a request.

        Args:
            context: Security context with auth information

        Returns:
            Dict with validation results
        """
        if not self.enabled:
            return {"valid": True, "message": "Auth security disabled"}

        try:
            user_id = getattr(context, "user_id", None)
            ip_address = getattr(context, "ip_address", None)
            device_id = getattr(context, "device_id", None)

            # Check brute force protection
            if ip_address:
                bf_check = self._check_brute_force_protection(ip_address)
                if not bf_check["allowed"]:
                    self.metrics.brute_force_blocks += 1
                    return {
                        "valid": False,
                        "message": bf_check["message"],
                        "block_type": "brute_force",
                    }

            # Validate device trust
            if self.device_tracking_enabled and device_id:
                device_check = self._validate_device_trust(
                    device_id, ip_address, user_id
                )
                if not device_check["trusted"]:
                    return {
                        "valid": False,
                        "message": device_check["message"],
                        "requires_mfa": True,
                    }

            # Perform risk assessment
            if self.risk_assessment_enabled:
                risk_score = self._calculate_risk_score(context)
                self.metrics.risk_assessments += 1

                if risk_score >= self.risk_thresholds["high"]:
                    self.metrics.high_risk_auths += 1
                    return {
                        "valid": False,
                        "message": f"High risk authentication attempt (score: {risk_score})",
                        "risk_score": risk_score,
                        "requires_additional_verification": True,
                    }

            return {"valid": True, "message": "Authentication security validated"}

        except Exception as e:
            logger.error(f"Error in auth security validation: {e}")
            return {"valid": False, "message": f"Auth security error: {str(e)}"}

    def _check_brute_force_protection(self, ip_address: str) -> Dict[str, Any]:
        """Check if IP is blocked due to brute force attempts."""
        if ip_address not in self.brute_force_tracking:
            return {"allowed": True}

        tracking = self.brute_force_tracking[ip_address]
        current_time = datetime.now(timezone.utc)

        # Check if still blocked
        if tracking.get("is_blocked", False):
            block_until = tracking.get("block_until")
            if block_until and current_time < block_until:
                remaining = block_until - current_time
                return {
                    "allowed": False,
                    "message": f"IP blocked due to brute force attempts. "
                    f"Remaining: {remaining.total_seconds():.0f} seconds",
                }
            else:
                # Block expired, reset tracking
                tracking["is_blocked"] = False
                tracking["block_until"] = None

        return {"allowed": True}

    def _validate_device_trust(
        self, device_id: str, ip_address: str, user_id: str
    ) -> Dict[str, Any]:
        """Validate device trust status."""
        if device_id in self.trusted_devices:
            return {"trusted": True, "message": "Device is trusted"}

        if device_id not in self.known_devices:
            # New device
            self.known_devices[device_id] = {
                "device_id": device_id,
                "first_seen": datetime.now(timezone.utc),
                "last_seen": datetime.now(timezone.utc),
                "ip_addresses": {ip_address} if ip_address else set(),
                "user_id": user_id,
                "trust_score": 0,
                "is_trusted": False,
            }

            return {
                "trusted": False,
                "message": "Unknown device - additional verification required",
                "device_status": "unknown",
            }

        # Known but untrusted device
        device_info = self.known_devices[device_id]
        device_info["last_seen"] = datetime.now(timezone.utc)

        if ip_address:
            device_info["ip_addresses"].add(ip_address)

        # Check if device should be auto-trusted
        trust_score = self._calculate_device_trust_score(device_info, ip_address)

        if trust_score >= 80:  # High trust score
            device_info["is_trusted"] = True
            device_info["trust_score"] = trust_score
            self.trusted_devices.add(device_id)
            self.metrics.device_trust_grants += 1

            return {"trusted": True, "message": "Device auto-trusted based on behavior"}

        return {
            "trusted": False,
            "message": f"Device trust score: {trust_score} - verification required",
            "trust_score": trust_score,
        }

    def _calculate_device_trust_score(
        self, device_info: Dict[str, Any], current_ip: str
    ) -> int:
        """Calculate trust score for a device."""
        score = 0

        # Age-based trust (older devices are more trusted)
        age_days = (datetime.now(timezone.utc) - device_info["first_seen"]).days
        score += min(age_days * 2, 40)  # Max 40 points for age

        # IP consistency (devices using same IPs are more trusted)
        if current_ip and current_ip in device_info["ip_addresses"]:
            score += 30

        # Usage frequency (more frequent use increases trust)
        last_seen = device_info["last_seen"]
        days_since_last_seen = (datetime.now(timezone.utc) - last_seen).days
        if days_since_last_seen <= 1:
            score += 20
        elif days_since_last_seen <= 7:
            score += 10

        return min(score, 100)

    def _calculate_risk_score(self, context: Any) -> int:
        """Calculate risk score for authentication attempt."""
        score = 0

        try:
            ip_address = getattr(context, "ip_address", None)
            user_agent = getattr(context, "user_agent", None)
            device_id = getattr(context, "device_id", None)

            # Unknown IP risk
            if ip_address and not self._is_known_ip(ip_address):
                score += 25

            # Unknown device risk
            if device_id and device_id not in self.known_devices:
                score += 30

            # Suspicious user agent
            if user_agent and self._is_suspicious_user_agent(user_agent):
                score += 20

            # Time-based risk
            current_hour = datetime.now(timezone.utc).hour
            if current_hour < 6 or current_hour > 22:
                score += 15

            # Brute force history
            if ip_address and ip_address in self.brute_force_tracking:
                failed_attempts = self.brute_force_tracking[ip_address].get(
                    "failed_attempts", 0
                )
                score += min(failed_attempts * 5, 20)

        except Exception as e:
            logger.error(f"Error calculating risk score: {e}")
            score = 50  # Default to medium risk

        return min(score, 100)

    def _is_known_ip(self, ip_address: str) -> bool:
        """Check if IP address is known for any user."""
        for device_info in self.known_devices.values():
            if ip_address in device_info.get("ip_addresses", set()):
                return True
        return False

    def _is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Check if user agent is suspicious."""
        suspicious_patterns = [
            "bot",
            "crawler",
            "spider",
            "scraper",
            "python",
            "curl",
            "wget",
            "java",
        ]

        user_agent_lower = user_agent.lower()
        return any(pattern in user_agent_lower for pattern in suspicious_patterns)

    def record_auth_attempt(
        self, ip_address: str, success: bool, user_id: Optional[str] = None
    ):
        """Record an authentication attempt for brute force protection."""
        if not self.enabled:
            return

        self.metrics.total_auth_attempts += 1

        if success:
            self.metrics.successful_auths += 1
            # Clear brute force tracking on success
            if ip_address in self.brute_force_tracking:
                del self.brute_force_tracking[ip_address]
            return

        self.metrics.failed_auths += 1

        # Record failed attempt
        current_time = datetime.now(timezone.utc)

        if ip_address not in self.brute_force_tracking:
            self.brute_force_tracking[ip_address] = {
                "ip_address": ip_address,
                "failed_attempts": 0,
                "first_attempt": current_time,
                "last_attempt": current_time,
                "is_blocked": False,
                "block_until": None,
                "user_id": user_id,
            }

        tracking = self.brute_force_tracking[ip_address]
        tracking["failed_attempts"] += 1
        tracking["last_attempt"] = current_time

        # Check if should block
        if tracking["failed_attempts"] >= self.max_attempts:
            tracking["is_blocked"] = True
            tracking["block_until"] = current_time + timedelta(
                minutes=self.lockout_duration_minutes
            )

            logger.warning(
                f"IP {ip_address} blocked due to {tracking['failed_attempts']} failed attempts"
            )

    def grant_device_trust(self, device_id: str, user_id: str):
        """Manually grant trust to a device."""
        if device_id not in self.known_devices:
            self.known_devices[device_id] = {
                "device_id": device_id,
                "first_seen": datetime.now(timezone.utc),
                "last_seen": datetime.now(timezone.utc),
                "ip_addresses": set(),
                "user_id": user_id,
                "trust_score": 100,
                "is_trusted": True,
            }
        else:
            self.known_devices[device_id]["is_trusted"] = True
            self.known_devices[device_id]["trust_score"] = 100

        self.trusted_devices.add(device_id)
        self.metrics.device_trust_grants += 1

        logger.info(f"Device trust granted for device {device_id}")

    def revoke_device_trust(self, device_id: str):
        """Revoke trust from a device."""
        if device_id in self.trusted_devices:
            self.trusted_devices.remove(device_id)

        if device_id in self.known_devices:
            self.known_devices[device_id]["is_trusted"] = False
            self.known_devices[device_id]["trust_score"] = 0

        logger.info(f"Device trust revoked for device {device_id}")

    def get_auth_security_status(self) -> Dict[str, Any]:
        """Get authentication security status."""
        if not self.enabled:
            return {"enabled": False}

        return {
            "enabled": True,
            "metrics": {
                "total_auth_attempts": self.metrics.total_auth_attempts,
                "successful_auths": self.metrics.successful_auths,
                "failed_auths": self.metrics.failed_auths,
                "brute_force_blocks": self.metrics.brute_force_blocks,
                "device_trust_grants": self.metrics.device_trust_grants,
                "risk_assessments": self.metrics.risk_assessments,
                "high_risk_auths": self.metrics.high_risk_auths,
            },
            "brute_force_tracking": {
                "active_blocks": len(
                    [t for t in self.brute_force_tracking.values() if t["is_blocked"]]
                ),
                "total_tracked_ips": len(self.brute_force_tracking),
            },
            "device_tracking": {
                "known_devices": len(self.known_devices),
                "trusted_devices": len(self.trusted_devices),
            },
            "config": {
                "max_attempts": self.max_attempts,
                "lockout_duration_minutes": self.lockout_duration_minutes,
                "device_tracking_enabled": self.device_tracking_enabled,
                "risk_assessment_enabled": self.risk_assessment_enabled,
            },
        }

    def reset_brute_force_tracking(self, ip_address: str):
        """Reset brute force tracking for an IP."""
        if ip_address in self.brute_force_tracking:
            del self.brute_force_tracking[ip_address]
            logger.info(f"Brute force tracking reset for IP {ip_address}")

    def cleanup_expired_blocks(self):
        """Clean up expired brute force blocks."""
        current_time = datetime.now(timezone.utc)
        expired_ips = []

        for ip, tracking in self.brute_force_tracking.items():
            if (
                tracking.get("is_blocked")
                and tracking.get("block_until")
                and current_time > tracking["block_until"]
            ):
                tracking["is_blocked"] = False
                tracking["block_until"] = None
                logger.info(f"Brute force block expired for IP {ip}")

    def update_config(self, new_config: Dict[str, Any]):
        """Update authentication security configuration."""
        if not self.enabled:
            return

        self.config.update(new_config)
        self.max_attempts = new_config.get("max_attempts", self.max_attempts)
        self.lockout_duration_minutes = new_config.get(
            "lockout_duration_minutes", self.lockout_duration_minutes
        )
        self.device_tracking_enabled = new_config.get(
            "device_tracking", self.device_tracking_enabled
        )
        self.risk_assessment_enabled = new_config.get(
            "risk_assessment", self.risk_assessment_enabled
        )

        logger.info("Authentication security configuration updated")

    async def shutdown(self):
        """Shutdown the authentication security integration."""
        logger.info("Authentication security integration shut down")


__all__ = ["AuthSecurityIntegration", "AuthSecurityMetrics"]
