"""
Subscription Management API for NetLink

This API provides comprehensive subscription and tier management for external payment integration:
- Admin API for managing user subscriptions
- Tier management and upgrades/downgrades
- External payment provider integration
- Subscription lifecycle management
- Usage tracking and limits enforcement
- Billing and payment history
- Webhook support for payment events
"""

import asyncio
import json
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from fastapi import APIRouter, HTTPException, Depends, Request, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import hmac
import hashlib
import secrets

from app.logger_config import logger
from app.profiles.advanced_profile_system import (
    advanced_profile_system, UserTier, SubscriptionStatus, UserSubscription
)

# Security
security = HTTPBearer()

class SubscriptionTier(str, Enum):
    """Available subscription tiers."""
    FREE = "free"
    BASIC = "basic"
    PREMIUM = "premium"
    VIP = "vip"
    ENTERPRISE = "enterprise"

class PaymentProvider(str, Enum):
    """Supported payment providers."""
    STRIPE = "stripe"
    PAYPAL = "paypal"
    PADDLE = "paddle"
    CUSTOM = "custom"

# Pydantic models for API requests/responses
class SubscriptionCreateRequest(BaseModel):
    user_id: int
    subscription_tier: SubscriptionTier
    billing_cycle: str = Field(default="monthly", regex="^(monthly|yearly|lifetime)$")
    payment_provider: PaymentProvider
    external_subscription_id: Optional[str] = None
    amount_paid: float = Field(ge=0)
    currency: str = Field(default="USD", min_length=3, max_length=3)
    features_enabled: List[str] = Field(default_factory=list)
    usage_limits: Dict[str, int] = Field(default_factory=dict)
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None

class SubscriptionUpdateRequest(BaseModel):
    subscription_tier: Optional[SubscriptionTier] = None
    status: Optional[SubscriptionStatus] = None
    billing_cycle: Optional[str] = Field(None, regex="^(monthly|yearly|lifetime)$")
    amount_paid: Optional[float] = Field(None, ge=0)
    features_enabled: Optional[List[str]] = None
    usage_limits: Optional[Dict[str, int]] = None
    end_date: Optional[datetime] = None
    payment_method: Optional[str] = None

class TierUpgradeRequest(BaseModel):
    user_id: int
    new_tier: UserTier
    reason: str = "admin_upgrade"
    effective_immediately: bool = True
    grant_tier_benefits: bool = True

class WebhookEvent(BaseModel):
    event_type: str
    provider: PaymentProvider
    external_subscription_id: str
    user_id: Optional[int] = None
    event_data: Dict[str, Any]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SubscriptionResponse(BaseModel):
    user_id: int
    subscription_tier: str
    status: str
    start_date: datetime
    end_date: Optional[datetime]
    billing_cycle: str
    amount_paid: float
    currency: str
    features_enabled: List[str]
    usage_limits: Dict[str, int]
    external_subscription_id: Optional[str]
    payment_provider: Optional[str]
    next_billing_date: Optional[datetime]

class UsageTrackingRequest(BaseModel):
    user_id: int
    usage_type: str  # e.g., "api_calls", "storage_mb", "messages_sent"
    amount: int
    timestamp: Optional[datetime] = None

class SubscriptionManagementAPI:
    """Comprehensive subscription management API."""
    
    def __init__(self):
        self.router = APIRouter(prefix="/api/v1/subscriptions", tags=["subscriptions"])
        self.webhook_secrets: Dict[PaymentProvider, str] = {}
        
        # Usage tracking
        self.usage_tracking: Dict[int, Dict[str, List[Dict[str, Any]]]] = {}
        
        # Subscription tier configurations
        self.tier_configs = {
            SubscriptionTier.FREE: {
                "price_monthly": 0.0,
                "price_yearly": 0.0,
                "features": ["basic_messaging", "file_sharing_1mb"],
                "limits": {
                    "api_calls_per_day": 100,
                    "storage_mb": 100,
                    "messages_per_day": 1000
                },
                "user_tier": UserTier.BASIC
            },
            SubscriptionTier.BASIC: {
                "price_monthly": 9.99,
                "price_yearly": 99.99,
                "features": ["basic_messaging", "file_sharing_10mb", "custom_themes"],
                "limits": {
                    "api_calls_per_day": 1000,
                    "storage_mb": 1000,
                    "messages_per_day": 10000
                },
                "user_tier": UserTier.BASIC
            },
            SubscriptionTier.PREMIUM: {
                "price_monthly": 19.99,
                "price_yearly": 199.99,
                "features": ["premium_messaging", "file_sharing_100mb", "custom_themes", "priority_support"],
                "limits": {
                    "api_calls_per_day": 5000,
                    "storage_mb": 5000,
                    "messages_per_day": 50000
                },
                "user_tier": UserTier.PREMIUM
            },
            SubscriptionTier.VIP: {
                "price_monthly": 49.99,
                "price_yearly": 499.99,
                "features": ["vip_messaging", "file_sharing_500mb", "custom_themes", "priority_support", "exclusive_features"],
                "limits": {
                    "api_calls_per_day": 20000,
                    "storage_mb": 20000,
                    "messages_per_day": -1  # Unlimited
                },
                "user_tier": UserTier.VIP
            },
            SubscriptionTier.ENTERPRISE: {
                "price_monthly": 99.99,
                "price_yearly": 999.99,
                "features": ["enterprise_messaging", "unlimited_file_sharing", "custom_themes", "priority_support", "exclusive_features", "api_access"],
                "limits": {
                    "api_calls_per_day": -1,  # Unlimited
                    "storage_mb": -1,  # Unlimited
                    "messages_per_day": -1  # Unlimited
                },
                "user_tier": UserTier.VIP
            }
        }
        
        # Initialize webhook secrets
        self._initialize_webhook_secrets()
        
        # Setup routes
        self._setup_routes()
        
        logger.info("Subscription Management API initialized")
    
    def _initialize_webhook_secrets(self):
        """Initialize webhook secrets for payment providers."""
        for provider in PaymentProvider:
            self.webhook_secrets[provider] = secrets.token_urlsafe(32)
        
        logger.info("Webhook secrets initialized for all payment providers")
    
    def _setup_routes(self):
        """Setup API routes."""
        
        @self.router.post("/create", response_model=SubscriptionResponse)
        async def create_subscription(
            request: SubscriptionCreateRequest,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Create a new subscription for a user."""
            # Verify admin token
            if not await self._verify_admin_token(credentials.credentials):
                raise HTTPException(status_code=401, detail="Invalid admin token")
            
            try:
                # Get tier configuration
                tier_config = self.tier_configs.get(request.subscription_tier)
                if not tier_config:
                    raise HTTPException(status_code=400, detail="Invalid subscription tier")
                
                # Create subscription data
                subscription_data = {
                    "tier": request.subscription_tier.value,
                    "status": "active",
                    "billing_cycle": request.billing_cycle,
                    "payment_provider": request.payment_provider.value,
                    "external_subscription_id": request.external_subscription_id,
                    "amount_paid": request.amount_paid,
                    "currency": request.currency,
                    "features_enabled": request.features_enabled or tier_config["features"],
                    "usage_limits": request.usage_limits or tier_config["limits"]
                }
                
                if request.start_date:
                    subscription_data["start_date"] = request.start_date.isoformat()
                if request.end_date:
                    subscription_data["end_date"] = request.end_date.isoformat()
                
                # Set subscription in profile system
                success = await advanced_profile_system.set_user_subscription(
                    request.user_id, subscription_data
                )
                
                if not success:
                    raise HTTPException(status_code=400, detail="Failed to create subscription")
                
                # Upgrade user tier if specified
                if tier_config["user_tier"]:
                    await advanced_profile_system.update_user_profile(
                        request.user_id,
                        {"tier": tier_config["user_tier"].value}
                    )
                
                # Get created subscription
                profile = await advanced_profile_system.get_user_profile(request.user_id)
                if not profile or not profile.subscription:
                    raise HTTPException(status_code=500, detail="Subscription creation failed")
                
                return self._subscription_to_response(profile.subscription)
                
            except Exception as e:
                logger.error(f"Failed to create subscription: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.router.get("/{user_id}", response_model=SubscriptionResponse)
        async def get_subscription(
            user_id: int,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Get subscription details for a user."""
            if not await self._verify_admin_token(credentials.credentials):
                raise HTTPException(status_code=401, detail="Invalid admin token")
            
            try:
                profile = await advanced_profile_system.get_user_profile(user_id)
                if not profile or not profile.subscription:
                    raise HTTPException(status_code=404, detail="Subscription not found")
                
                return self._subscription_to_response(profile.subscription)
                
            except Exception as e:
                logger.error(f"Failed to get subscription: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.router.put("/{user_id}", response_model=SubscriptionResponse)
        async def update_subscription(
            user_id: int,
            request: SubscriptionUpdateRequest,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Update an existing subscription."""
            if not await self._verify_admin_token(credentials.credentials):
                raise HTTPException(status_code=401, detail="Invalid admin token")
            
            try:
                profile = await advanced_profile_system.get_user_profile(user_id)
                if not profile or not profile.subscription:
                    raise HTTPException(status_code=404, detail="Subscription not found")
                
                # Update subscription fields
                subscription = profile.subscription
                
                if request.subscription_tier:
                    subscription.subscription_tier = request.subscription_tier.value
                    # Update features and limits based on new tier
                    tier_config = self.tier_configs.get(request.subscription_tier)
                    if tier_config:
                        subscription.features_enabled = tier_config["features"]
                        subscription.usage_limits = tier_config["limits"]
                
                if request.status:
                    subscription.status = request.status
                
                if request.billing_cycle:
                    subscription.billing_cycle = request.billing_cycle
                
                if request.amount_paid is not None:
                    subscription.amount_paid = request.amount_paid
                    subscription.last_payment_date = datetime.now(timezone.utc)
                
                if request.features_enabled is not None:
                    subscription.features_enabled = request.features_enabled
                
                if request.usage_limits is not None:
                    subscription.usage_limits = request.usage_limits
                
                if request.end_date:
                    subscription.end_date = request.end_date
                
                if request.payment_method:
                    subscription.payment_method = request.payment_method
                
                # Calculate next billing date
                if subscription.billing_cycle == "monthly":
                    subscription.next_billing_date = datetime.now(timezone.utc) + timedelta(days=30)
                elif subscription.billing_cycle == "yearly":
                    subscription.next_billing_date = datetime.now(timezone.utc) + timedelta(days=365)
                
                # Save updated profile
                await advanced_profile_system._save_user_profile(user_id)
                
                return self._subscription_to_response(subscription)
                
            except Exception as e:
                logger.error(f"Failed to update subscription: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.router.delete("/{user_id}")
        async def cancel_subscription(
            user_id: int,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Cancel a user's subscription."""
            if not await self._verify_admin_token(credentials.credentials):
                raise HTTPException(status_code=401, detail="Invalid admin token")
            
            try:
                profile = await advanced_profile_system.get_user_profile(user_id)
                if not profile or not profile.subscription:
                    raise HTTPException(status_code=404, detail="Subscription not found")
                
                # Cancel subscription
                profile.subscription.status = SubscriptionStatus.CANCELLED
                profile.subscription.end_date = datetime.now(timezone.utc)
                
                # Downgrade user tier to basic
                await advanced_profile_system.update_user_profile(
                    user_id,
                    {"tier": UserTier.BASIC.value}
                )
                
                # Save changes
                await advanced_profile_system._save_user_profile(user_id)
                
                return {"message": "Subscription cancelled successfully"}
                
            except Exception as e:
                logger.error(f"Failed to cancel subscription: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.router.post("/tier/upgrade")
        async def upgrade_user_tier(
            request: TierUpgradeRequest,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Upgrade a user's tier (admin only)."""
            if not await self._verify_admin_token(credentials.credentials):
                raise HTTPException(status_code=401, detail="Invalid admin token")
            
            try:
                success = await advanced_profile_system.update_user_profile(
                    request.user_id,
                    {"tier": request.new_tier.value}
                )
                
                if not success:
                    raise HTTPException(status_code=400, detail="Failed to upgrade tier")
                
                # Grant tier benefits if requested
                if request.grant_tier_benefits:
                    await self._grant_tier_benefits(request.user_id, request.new_tier)
                
                return {"message": f"User tier upgraded to {request.new_tier.value}"}
                
            except Exception as e:
                logger.error(f"Failed to upgrade tier: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.router.post("/usage/track")
        async def track_usage(
            request: UsageTrackingRequest,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Track usage for a user."""
            if not await self._verify_admin_token(credentials.credentials):
                raise HTTPException(status_code=401, detail="Invalid admin token")
            
            try:
                await self._track_user_usage(
                    request.user_id,
                    request.usage_type,
                    request.amount,
                    request.timestamp or datetime.now(timezone.utc)
                )
                
                return {"message": "Usage tracked successfully"}
                
            except Exception as e:
                logger.error(f"Failed to track usage: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.router.get("/usage/{user_id}")
        async def get_usage_stats(
            user_id: int,
            usage_type: Optional[str] = None,
            days: int = 30,
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Get usage statistics for a user."""
            if not await self._verify_admin_token(credentials.credentials):
                raise HTTPException(status_code=401, detail="Invalid admin token")
            
            try:
                return await self._get_usage_stats(user_id, usage_type, days)
                
            except Exception as e:
                logger.error(f"Failed to get usage stats: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.router.post("/webhook/{provider}")
        async def handle_webhook(
            provider: PaymentProvider,
            request: Request,
            background_tasks: BackgroundTasks
        ):
            """Handle webhooks from payment providers."""
            try:
                # Get raw body for signature verification
                body = await request.body()
                
                # Verify webhook signature
                if not await self._verify_webhook_signature(provider, body, request.headers):
                    raise HTTPException(status_code=401, detail="Invalid webhook signature")
                
                # Parse webhook data
                webhook_data = json.loads(body.decode())
                
                # Process webhook in background
                background_tasks.add_task(
                    self._process_webhook,
                    provider,
                    webhook_data
                )
                
                return {"message": "Webhook received"}
                
            except Exception as e:
                logger.error(f"Webhook processing failed: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.router.get("/tiers/config")
        async def get_tier_configurations(
            credentials: HTTPAuthorizationCredentials = Depends(security)
        ):
            """Get subscription tier configurations."""
            if not await self._verify_admin_token(credentials.credentials):
                raise HTTPException(status_code=401, detail="Invalid admin token")
            
            return self.tier_configs

    async def _verify_admin_token(self, token: str) -> bool:
        """Verify admin API token."""
        # In production, this should verify against a secure token store
        # For now, we'll use a simple check
        admin_tokens = [
            "netlink_admin_2024_secure_token",
            "subscription_api_admin_key"
        ]
        return token in admin_tokens

    def _subscription_to_response(self, subscription: UserSubscription) -> SubscriptionResponse:
        """Convert UserSubscription to API response."""
        return SubscriptionResponse(
            user_id=subscription.user_id,
            subscription_tier=subscription.subscription_tier,
            status=subscription.status.value,
            start_date=subscription.start_date,
            end_date=subscription.end_date,
            billing_cycle=subscription.billing_cycle,
            amount_paid=subscription.amount_paid,
            currency=subscription.currency,
            features_enabled=subscription.features_enabled or [],
            usage_limits=subscription.usage_limits or {},
            external_subscription_id=subscription.external_subscription_id,
            payment_provider=subscription.payment_provider,
            next_billing_date=subscription.next_billing_date
        )

    async def _grant_tier_benefits(self, user_id: int, tier: UserTier):
        """Grant benefits for a specific tier."""
        try:
            # Award tier-specific badges
            if tier == UserTier.ALPHA_TESTER:
                await advanced_profile_system._award_badge(
                    user_id, "alpha_tester", "Upgraded to Alpha Tester tier"
                )
            elif tier == UserTier.BETA_TESTER:
                await advanced_profile_system._award_badge(
                    user_id, "beta_tester", "Upgraded to Beta Tester tier"
                )

            # Grant experience points based on tier
            tier_xp_rewards = {
                UserTier.PREMIUM: 500,
                UserTier.VIP: 1000,
                UserTier.ALPHA_TESTER: 2000,
                UserTier.BETA_TESTER: 1500,
                UserTier.DEVELOPER: 3000,
                UserTier.MODERATOR: 2500,
                UserTier.ADMIN: 5000
            }

            if tier in tier_xp_rewards:
                profile = await advanced_profile_system.get_user_profile(user_id)
                if profile:
                    profile.experience_points += tier_xp_rewards[tier]
                    await advanced_profile_system._check_level_up(profile)
                    await advanced_profile_system._save_user_profile(user_id)

            logger.info(f"Granted tier benefits for user {user_id} tier {tier.value}")

        except Exception as e:
            logger.error(f"Failed to grant tier benefits: {e}")

    async def _track_user_usage(self, user_id: int, usage_type: str, amount: int, timestamp: datetime):
        """Track usage for a user."""
        try:
            if user_id not in self.usage_tracking:
                self.usage_tracking[user_id] = {}

            if usage_type not in self.usage_tracking[user_id]:
                self.usage_tracking[user_id][usage_type] = []

            # Add usage record
            usage_record = {
                "amount": amount,
                "timestamp": timestamp.isoformat(),
                "date": timestamp.date().isoformat()
            }

            self.usage_tracking[user_id][usage_type].append(usage_record)

            # Keep only last 90 days of data
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=90)
            self.usage_tracking[user_id][usage_type] = [
                record for record in self.usage_tracking[user_id][usage_type]
                if datetime.fromisoformat(record["timestamp"]) > cutoff_date
            ]

            # Check if user is approaching limits
            await self._check_usage_limits(user_id, usage_type)

        except Exception as e:
            logger.error(f"Failed to track usage: {e}")

    async def _check_usage_limits(self, user_id: int, usage_type: str):
        """Check if user is approaching usage limits."""
        try:
            profile = await advanced_profile_system.get_user_profile(user_id)
            if not profile or not profile.subscription:
                return

            limits = profile.subscription.usage_limits
            if not limits or usage_type not in limits:
                return

            limit = limits[usage_type]
            if limit == -1:  # Unlimited
                return

            # Calculate current usage for today
            today = datetime.now(timezone.utc).date().isoformat()
            today_usage = sum(
                record["amount"] for record in self.usage_tracking.get(user_id, {}).get(usage_type, [])
                if record["date"] == today
            )

            # Check if approaching limit (80% threshold)
            if today_usage >= limit * 0.8:
                logger.warning(f"User {user_id} approaching {usage_type} limit: {today_usage}/{limit}")

                # Could send notification here
                await self._send_usage_warning(user_id, usage_type, today_usage, limit)

        except Exception as e:
            logger.error(f"Failed to check usage limits: {e}")

    async def _send_usage_warning(self, user_id: int, usage_type: str, current: int, limit: int):
        """Send usage warning to user."""
        try:
            # This would integrate with notification system
            logger.info(f"Usage warning for user {user_id}: {usage_type} {current}/{limit}")

            # Could add to user's notifications or send email
            profile = await advanced_profile_system.get_user_profile(user_id)
            if profile:
                if "notifications" not in profile.custom_fields:
                    profile.custom_fields["notifications"] = []

                profile.custom_fields["notifications"].append({
                    "type": "usage_warning",
                    "message": f"You're approaching your {usage_type} limit ({current}/{limit})",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "read": False
                })

                await advanced_profile_system._save_user_profile(user_id)

        except Exception as e:
            logger.error(f"Failed to send usage warning: {e}")

    async def _get_usage_stats(self, user_id: int, usage_type: Optional[str], days: int) -> Dict[str, Any]:
        """Get usage statistics for a user."""
        try:
            if user_id not in self.usage_tracking:
                return {"usage": {}, "summary": {}}

            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

            usage_data = {}
            summary = {}

            user_usage = self.usage_tracking[user_id]

            for utype, records in user_usage.items():
                if usage_type and utype != usage_type:
                    continue

                # Filter by date range
                filtered_records = [
                    record for record in records
                    if datetime.fromisoformat(record["timestamp"]) > cutoff_date
                ]

                # Calculate statistics
                total_usage = sum(record["amount"] for record in filtered_records)
                daily_usage = {}

                for record in filtered_records:
                    date = record["date"]
                    if date not in daily_usage:
                        daily_usage[date] = 0
                    daily_usage[date] += record["amount"]

                usage_data[utype] = {
                    "total": total_usage,
                    "daily": daily_usage,
                    "records": filtered_records
                }

                summary[utype] = {
                    "total": total_usage,
                    "average_daily": total_usage / max(days, 1),
                    "peak_day": max(daily_usage.values()) if daily_usage else 0,
                    "days_with_usage": len(daily_usage)
                }

            return {
                "usage": usage_data,
                "summary": summary,
                "period_days": days,
                "user_id": user_id
            }

        except Exception as e:
            logger.error(f"Failed to get usage stats: {e}")
            return {"error": str(e)}

    async def _verify_webhook_signature(self, provider: PaymentProvider, body: bytes, headers: Dict[str, str]) -> bool:
        """Verify webhook signature from payment provider."""
        try:
            secret = self.webhook_secrets.get(provider)
            if not secret:
                return False

            # Different providers use different header names
            signature_headers = {
                PaymentProvider.STRIPE: "stripe-signature",
                PaymentProvider.PAYPAL: "paypal-transmission-sig",
                PaymentProvider.PADDLE: "paddle-signature",
                PaymentProvider.CUSTOM: "x-webhook-signature"
            }

            signature_header = signature_headers.get(provider, "x-webhook-signature")
            received_signature = headers.get(signature_header)

            if not received_signature:
                return False

            # Calculate expected signature
            expected_signature = hmac.new(
                secret.encode(),
                body,
                hashlib.sha256
            ).hexdigest()

            # Compare signatures
            return hmac.compare_digest(received_signature, expected_signature)

        except Exception as e:
            logger.error(f"Failed to verify webhook signature: {e}")
            return False

    async def _process_webhook(self, provider: PaymentProvider, webhook_data: Dict[str, Any]):
        """Process webhook from payment provider."""
        try:
            event_type = webhook_data.get("type") or webhook_data.get("event_type")

            if not event_type:
                logger.warning("Webhook missing event type")
                return

            # Handle different event types
            if event_type in ["payment.succeeded", "invoice.payment_succeeded"]:
                await self._handle_payment_success(provider, webhook_data)
            elif event_type in ["payment.failed", "invoice.payment_failed"]:
                await self._handle_payment_failure(provider, webhook_data)
            elif event_type in ["subscription.cancelled", "subscription.deleted"]:
                await self._handle_subscription_cancellation(provider, webhook_data)
            elif event_type in ["subscription.updated"]:
                await self._handle_subscription_update(provider, webhook_data)
            else:
                logger.info(f"Unhandled webhook event type: {event_type}")

        except Exception as e:
            logger.error(f"Failed to process webhook: {e}")

    async def _handle_payment_success(self, provider: PaymentProvider, webhook_data: Dict[str, Any]):
        """Handle successful payment webhook."""
        try:
            external_id = webhook_data.get("subscription_id") or webhook_data.get("id")
            amount = webhook_data.get("amount") or webhook_data.get("amount_paid", 0)

            # Find user by external subscription ID
            user_id = await self._find_user_by_external_id(external_id)
            if not user_id:
                logger.warning(f"No user found for external subscription ID: {external_id}")
                return

            # Update subscription
            profile = await advanced_profile_system.get_user_profile(user_id)
            if profile and profile.subscription:
                profile.subscription.last_payment_date = datetime.now(timezone.utc)
                profile.subscription.amount_paid = float(amount) / 100  # Convert from cents
                profile.subscription.status = SubscriptionStatus.ACTIVE

                # Extend subscription if needed
                if profile.subscription.billing_cycle == "monthly":
                    profile.subscription.next_billing_date = datetime.now(timezone.utc) + timedelta(days=30)
                elif profile.subscription.billing_cycle == "yearly":
                    profile.subscription.next_billing_date = datetime.now(timezone.utc) + timedelta(days=365)

                await advanced_profile_system._save_user_profile(user_id)

                logger.info(f"Payment success processed for user {user_id}")

        except Exception as e:
            logger.error(f"Failed to handle payment success: {e}")

    async def _handle_payment_failure(self, provider: PaymentProvider, webhook_data: Dict[str, Any]):
        """Handle failed payment webhook."""
        try:
            external_id = webhook_data.get("subscription_id") or webhook_data.get("id")

            # Find user by external subscription ID
            user_id = await self._find_user_by_external_id(external_id)
            if not user_id:
                return

            # Update subscription status
            profile = await advanced_profile_system.get_user_profile(user_id)
            if profile and profile.subscription:
                profile.subscription.status = SubscriptionStatus.PAST_DUE
                await advanced_profile_system._save_user_profile(user_id)

                logger.warning(f"Payment failure processed for user {user_id}")

        except Exception as e:
            logger.error(f"Failed to handle payment failure: {e}")

    async def _handle_subscription_cancellation(self, provider: PaymentProvider, webhook_data: Dict[str, Any]):
        """Handle subscription cancellation webhook."""
        try:
            external_id = webhook_data.get("subscription_id") or webhook_data.get("id")

            # Find user by external subscription ID
            user_id = await self._find_user_by_external_id(external_id)
            if not user_id:
                return

            # Cancel subscription
            profile = await advanced_profile_system.get_user_profile(user_id)
            if profile and profile.subscription:
                profile.subscription.status = SubscriptionStatus.CANCELLED
                profile.subscription.end_date = datetime.now(timezone.utc)

                # Downgrade user tier
                await advanced_profile_system.update_user_profile(
                    user_id,
                    {"tier": UserTier.BASIC.value}
                )

                logger.info(f"Subscription cancellation processed for user {user_id}")

        except Exception as e:
            logger.error(f"Failed to handle subscription cancellation: {e}")

    async def _handle_subscription_update(self, provider: PaymentProvider, webhook_data: Dict[str, Any]):
        """Handle subscription update webhook."""
        try:
            external_id = webhook_data.get("subscription_id") or webhook_data.get("id")

            # Find user by external subscription ID
            user_id = await self._find_user_by_external_id(external_id)
            if not user_id:
                return

            # Update subscription details based on webhook data
            profile = await advanced_profile_system.get_user_profile(user_id)
            if profile and profile.subscription:
                # Update relevant fields from webhook
                if "status" in webhook_data:
                    status_map = {
                        "active": SubscriptionStatus.ACTIVE,
                        "cancelled": SubscriptionStatus.CANCELLED,
                        "past_due": SubscriptionStatus.PAST_DUE,
                        "unpaid": SubscriptionStatus.PAST_DUE
                    }
                    new_status = status_map.get(webhook_data["status"])
                    if new_status:
                        profile.subscription.status = new_status

                await advanced_profile_system._save_user_profile(user_id)

                logger.info(f"Subscription update processed for user {user_id}")

        except Exception as e:
            logger.error(f"Failed to handle subscription update: {e}")

    async def _find_user_by_external_id(self, external_id: str) -> Optional[int]:
        """Find user ID by external subscription ID."""
        try:
            # Search through all profiles for matching external subscription ID
            for user_id, profile in advanced_profile_system.profiles.items():
                if (profile.subscription and
                    profile.subscription.external_subscription_id == external_id):
                    return user_id

            return None

        except Exception as e:
            logger.error(f"Failed to find user by external ID: {e}")
            return None

# Global subscription management API instance
subscription_api = SubscriptionManagementAPI()
