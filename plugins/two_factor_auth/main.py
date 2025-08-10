import asyncio
import base64
import hashlib
import json
import logging
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import qrcode
except ImportError:
    qrcode = None
try:
    import pyotp
except ImportError:
    pyotp = None

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from plugins_internal import EnhancedBasePlugin, EnhancedPluginConfig

class TwoFactorAuthPlugin(EnhancedBasePlugin):
    """Advanced Two-Factor Authentication Plugin using the PlexiChat SDK."""

    def __init__(self):
        config = EnhancedPluginConfig(
            name="TwoFactorAuth",
            version="1.1.0",
            description="Advanced Two-Factor Authentication plugin using the PlexiChat SDK.",
            author="PlexiChat Security Team",
            plugin_type="security_node",
            tags=["authentication", "security", "2fa", "totp"],
        )
        super().__init__(config)
        self.router = APIRouter(prefix="/api/v1/2fa", tags=["Two-Factor Authentication"])
        self._setup_routes()

    async def _initialize(self):
        """Initialize the plugin."""
        self.logger.info("Initializing Two-Factor Authentication Plugin V2.")
        # No database initialization needed, SDK handles it.

    def get_api_router(self) -> APIRouter:
        """Returns the API router for this plugin."""
        return self.router

    # --- Core Logic using SDK ---

    async def _get_user_data(self, user_id: str) -> Dict[str, Any]:
        """Gets all 2FA data for a user from the unified database."""
        return await self.api.db_get_value(f"user:{user_id}", default={})

    async def _save_user_data(self, user_id: str, data: Dict[str, Any]) -> bool:
        """Saves all 2FA data for a user to the unified database."""
        return await self.api.db_set_value(f"user:{user_id}", data)

    def _generate_recovery_codes(self, user_data: Dict[str, Any]) -> List[str]:
        """Generates and stores hashes of new recovery codes."""
        codes = [secrets.token_hex(5).upper() for _ in range(10)]
        user_data["recovery_codes"] = [
            {"code_hash": hashlib.sha256(c.encode()).hexdigest(), "used": False} for c in codes
        ]
        return codes

    def _use_recovery_code(self, user_data: Dict[str, Any], code: str) -> bool:
        """Checks a recovery code, marks it as used if valid, and returns True."""
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        for recovery_code in user_data.get("recovery_codes", []):
            if recovery_code["code_hash"] == code_hash and not recovery_code["used"]:
                recovery_code["used"] = True
                self.logger.info(f"Recovery code used for user {user_data.get('user_id')}")
                return True
        return False

    # --- API Implementation ---

    def _setup_routes(self):
        """Setup API routes for the plugin."""

        class SetupRequest(BaseModel):
            user_id: str
            method: str = "totp"

        @self.router.post("/setup")
        async def setup_2fa(req: SetupRequest):
            if req.method != "totp":
                raise HTTPException(status_code=400, detail="Unsupported 2FA method.")
            if not pyotp or not qrcode:
                raise HTTPException(status_code=501, detail="Required libraries (pyotp, qrcode) are not installed.")

            secret = pyotp.random_base32()
            user_data = await self._get_user_data(req.user_id)
            user_data.update({
                "user_id": req.user_id,
                "enabled": True,
                "method": "totp",
                "secret": secret,
                "devices": user_data.get("devices", []),
                "setup_at": datetime.now(timezone.utc).isoformat(),
            })

            recovery_codes = self._generate_recovery_codes(user_data)
            await self._save_user_data(req.user_id, user_data)

            totp = pyotp.TOTP(secret)
            provisioning_uri = totp.provisioning_uri(name=req.user_id, issuer_name="PlexiChat")

            self.logger.info(f"TOTP setup initiated for user: {req.user_id}")
            return {
                "secret": secret,
                "qr_code_uri": provisioning_uri,
                "recovery_codes": recovery_codes
            }

        class VerifyRequest(BaseModel):
            user_id: str
            code: str

        @self.router.post("/verify")
        async def verify_2fa(req: VerifyRequest):
            user_data = await self._get_user_data(req.user_id)
            if not user_data.get("enabled"):
                raise HTTPException(status_code=400, detail="2FA is not enabled for this user.")

            # 1. Try TOTP code
            if user_data.get("method") == "totp" and pyotp:
                totp = pyotp.TOTP(user_data.get("secret"))
                if totp.verify(req.code):
                    self.logger.info(f"Successful TOTP verification for user: {req.user_id}")
                    return {"success": True, "message": "Verification successful."}

            # 2. Try recovery code
            if self._use_recovery_code(user_data, req.code):
                await self._save_user_data(req.user_id, user_data)
                self.logger.info(f"Successful recovery code verification for user: {req.user_id}")
                return {"success": True, "message": "Verification successful using recovery code."}

            self.logger.warning(f"Failed 2FA verification attempt for user: {req.user_id}")
            raise HTTPException(status_code=401, detail="Invalid verification code.")

        class DisableRequest(BaseModel):
            user_id: str

        @self.router.post("/disable")
        async def disable_2fa(req: DisableRequest):
            user_data = await self._get_user_data(req.user_id)
            if not user_data or not user_data.get("enabled"):
                raise HTTPException(status_code=400, detail="2FA is not enabled for this user.")

            user_data["enabled"] = False
            user_data["secret"] = None # Invalidate the secret

            if await self._save_user_data(req.user_id, user_data):
                self.logger.info(f"2FA disabled for user: {req.user_id}")
                return {"success": True, "message": "2FA has been disabled."}
            else:
                raise HTTPException(status_code=500, detail="Failed to disable 2FA.")

        class RecoveryRequest(BaseModel):
            user_id: str

        @self.router.post("/recovery/regenerate")
        async def regenerate_recovery_codes(req: RecoveryRequest):
            user_data = await self._get_user_data(req.user_id)
            if not user_data.get("enabled"):
                raise HTTPException(status_code=400, detail="2FA is not enabled for this user.")

            codes = self._generate_recovery_codes(user_data)
            if await self._save_user_data(req.user_id, user_data):
                self.logger.info(f"Recovery codes regenerated for user: {req.user_id}")
                return {"recovery_codes": codes}
            else:
                raise HTTPException(status_code=500, detail="Failed to regenerate recovery codes.")

# This is how the plugin manager will instantiate the plugin
plugin = TwoFactorAuthPlugin()
