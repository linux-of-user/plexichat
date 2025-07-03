"""
AI-powered moderation service with support for multiple providers and endpoints.
Provides flexible, configurable AI moderation with human review integration.
"""

import asyncio
import json
import hashlib
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
import httpx
from dataclasses import dataclass

from netlink.app.models.advanced_moderation import (
    ModerationConfiguration, ModerationItem, AIModelEndpoint,
    ModerationAction, ModerationSeverity, ModerationStatus, ModerationSource,
    AIModelProvider
)
from netlink.app.models.enhanced_models import EnhancedUser
from netlink.app.logger_config import logger


@dataclass
class ModerationResult:
    """Result of AI moderation analysis."""
    confidence_score: float
    recommended_action: ModerationAction
    reasoning: str
    severity: ModerationSeverity
    categories: List[str]
    metadata: Dict[str, Any]
    processing_time_ms: float
    model_used: str
    requires_human_review: bool


@dataclass
class AIProviderConfig:
    """Configuration for AI provider."""
    provider: AIModelProvider
    model_name: str
    endpoint_url: str
    api_key: str
    request_format: Dict[str, Any]
    response_format: Dict[str, Any]
    timeout_seconds: int = 30
    max_retries: int = 3


class AIModerationService:
    """AI-powered moderation service with multi-provider support."""
    
    def __init__(self):
        self.providers: Dict[str, AIProviderConfig] = {}
        self.default_prompts = self._get_default_prompts()
        self.rate_limits: Dict[str, Dict[str, Any]] = {}
        
    async def configure_provider(
        self,
        config: ModerationConfiguration,
        endpoint: AIModelEndpoint
    ) -> bool:
        """Configure an AI provider for moderation."""
        try:
            provider_config = AIProviderConfig(
                provider=endpoint.provider,
                model_name=endpoint.model_name,
                endpoint_url=endpoint.endpoint_url,
                api_key=self._decrypt_api_key(endpoint.api_key_hash),
                request_format=endpoint.request_format,
                response_format=endpoint.response_format,
                timeout_seconds=endpoint.timeout_seconds,
                max_retries=endpoint.max_retries
            )
            
            # Test the provider
            test_result = await self._test_provider(provider_config)
            if test_result:
                self.providers[endpoint.endpoint_name] = provider_config
                logger.info(f"✅ Configured AI provider: {endpoint.endpoint_name}")
                return True
            else:
                logger.error(f"❌ Failed to configure AI provider: {endpoint.endpoint_name}")
                return False
                
        except Exception as e:
            logger.error(f"Error configuring AI provider {endpoint.endpoint_name}: {e}")
            return False
    
    async def moderate_content(
        self,
        content: str,
        content_type: str,
        config: ModerationConfiguration,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ModerationResult:
        """Moderate content using configured AI provider."""
        start_time = time.time()
        
        try:
            # Get provider configuration
            provider_name = self._get_provider_for_config(config)
            if not provider_name or provider_name not in self.providers:
                raise ValueError(f"No configured provider found for config {config.config_name}")
            
            provider_config = self.providers[provider_name]
            
            # Check rate limits
            if not await self._check_rate_limit(provider_name, config):
                raise Exception("Rate limit exceeded")
            
            # Prepare moderation request
            request_data = await self._prepare_moderation_request(
                content, content_type, provider_config, config, metadata
            )
            
            # Call AI provider
            ai_response = await self._call_ai_provider(provider_config, request_data)
            
            # Parse response
            result = await self._parse_ai_response(ai_response, provider_config, config)
            
            # Calculate processing time
            processing_time = (time.time() - start_time) * 1000
            result.processing_time_ms = processing_time
            result.model_used = f"{provider_config.provider.value}:{provider_config.model_name}"
            
            # Determine if human review is required
            result.requires_human_review = self._requires_human_review(result, config)
            
            logger.info(f"🤖 AI moderation completed: {result.confidence_score:.2f} confidence, {result.recommended_action.value}")
            
            return result
            
        except Exception as e:
            logger.error(f"AI moderation failed: {e}")
            # Return safe default result
            return ModerationResult(
                confidence_score=0.0,
                recommended_action=ModerationAction.FLAG,
                reasoning=f"AI moderation failed: {str(e)}",
                severity=ModerationSeverity.MEDIUM,
                categories=["error"],
                metadata={"error": str(e)},
                processing_time_ms=(time.time() - start_time) * 1000,
                model_used="error",
                requires_human_review=True
            )
    
    async def _prepare_moderation_request(
        self,
        content: str,
        content_type: str,
        provider_config: AIProviderConfig,
        config: ModerationConfiguration,
        metadata: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Prepare request data for AI provider."""
        
        # Get appropriate prompt for content type
        prompt = self._get_moderation_prompt(content_type, config)
        
        # Prepare request based on provider
        if provider_config.provider == AIModelProvider.OPENAI:
            return {
                "model": provider_config.model_name,
                "messages": [
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": content}
                ],
                "temperature": 0.1,
                "max_tokens": 500
            }
        
        elif provider_config.provider == AIModelProvider.ANTHROPIC:
            return {
                "model": provider_config.model_name,
                "messages": [
                    {"role": "user", "content": f"{prompt}\n\nContent to moderate: {content}"}
                ],
                "max_tokens": 500,
                "temperature": 0.1
            }
        
        elif provider_config.provider == AIModelProvider.CUSTOM:
            # Use custom format from configuration
            request_template = provider_config.request_format
            return self._fill_request_template(request_template, content, prompt, metadata)
        
        else:
            # Generic format
            return {
                "content": content,
                "prompt": prompt,
                "content_type": content_type,
                "metadata": metadata or {}
            }
    
    async def _call_ai_provider(
        self,
        provider_config: AIProviderConfig,
        request_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Call the AI provider API."""
        headers = {
            "Content-Type": "application/json"
        }
        
        # Add authentication headers
        if provider_config.provider == AIModelProvider.OPENAI:
            headers["Authorization"] = f"Bearer {provider_config.api_key}"
        elif provider_config.provider == AIModelProvider.ANTHROPIC:
            headers["x-api-key"] = provider_config.api_key
            headers["anthropic-version"] = "2023-06-01"
        else:
            headers["Authorization"] = f"Bearer {provider_config.api_key}"
        
        async with httpx.AsyncClient(timeout=provider_config.timeout_seconds) as client:
            for attempt in range(provider_config.max_retries + 1):
                try:
                    response = await client.post(
                        provider_config.endpoint_url,
                        json=request_data,
                        headers=headers
                    )
                    
                    if response.status_code == 200:
                        return response.json()
                    elif response.status_code == 429:  # Rate limited
                        if attempt < provider_config.max_retries:
                            await asyncio.sleep(2 ** attempt)  # Exponential backoff
                            continue
                        else:
                            raise Exception("Rate limit exceeded")
                    else:
                        raise Exception(f"API error: {response.status_code} - {response.text}")
                
                except httpx.TimeoutException:
                    if attempt < provider_config.max_retries:
                        await asyncio.sleep(1)
                        continue
                    else:
                        raise Exception("Request timeout")
        
        raise Exception("All retry attempts failed")
    
    async def _parse_ai_response(
        self,
        response: Dict[str, Any],
        provider_config: AIProviderConfig,
        config: ModerationConfiguration
    ) -> ModerationResult:
        """Parse AI provider response into ModerationResult."""
        
        try:
            if provider_config.provider == AIModelProvider.OPENAI:
                content = response["choices"][0]["message"]["content"]
                return self._parse_structured_response(content)
            
            elif provider_config.provider == AIModelProvider.ANTHROPIC:
                content = response["content"][0]["text"]
                return self._parse_structured_response(content)
            
            elif provider_config.provider == AIModelProvider.CUSTOM:
                # Use custom response format
                return self._parse_custom_response(response, provider_config.response_format)
            
            else:
                # Try to parse as structured response
                return self._parse_structured_response(str(response))
        
        except Exception as e:
            logger.error(f"Failed to parse AI response: {e}")
            # Return safe default
            return ModerationResult(
                confidence_score=0.5,
                recommended_action=ModerationAction.FLAG,
                reasoning="Failed to parse AI response",
                severity=ModerationSeverity.MEDIUM,
                categories=["parse_error"],
                metadata={"parse_error": str(e)},
                processing_time_ms=0,
                model_used="unknown",
                requires_human_review=True
            )
    
    def _parse_structured_response(self, content: str) -> ModerationResult:
        """Parse structured AI response."""
        try:
            # Try to parse as JSON first
            if content.strip().startswith("{"):
                data = json.loads(content)
                return ModerationResult(
                    confidence_score=float(data.get("confidence", 0.5)),
                    recommended_action=ModerationAction(data.get("action", "flag")),
                    reasoning=data.get("reasoning", "No reasoning provided"),
                    severity=ModerationSeverity(data.get("severity", "medium")),
                    categories=data.get("categories", []),
                    metadata=data.get("metadata", {}),
                    processing_time_ms=0,
                    model_used="",
                    requires_human_review=False
                )
            
            # Parse text response
            lines = content.strip().split('\n')
            result_data = {}
            
            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    result_data[key.strip().lower()] = value.strip()
            
            return ModerationResult(
                confidence_score=float(result_data.get("confidence", "0.5")),
                recommended_action=ModerationAction(result_data.get("action", "flag")),
                reasoning=result_data.get("reasoning", content),
                severity=ModerationSeverity(result_data.get("severity", "medium")),
                categories=result_data.get("categories", "").split(",") if result_data.get("categories") else [],
                metadata={"raw_response": content},
                processing_time_ms=0,
                model_used="",
                requires_human_review=False
            )
        
        except Exception as e:
            logger.error(f"Failed to parse structured response: {e}")
            return ModerationResult(
                confidence_score=0.5,
                recommended_action=ModerationAction.FLAG,
                reasoning=content,
                severity=ModerationSeverity.MEDIUM,
                categories=["unparsed"],
                metadata={"raw_response": content, "parse_error": str(e)},
                processing_time_ms=0,
                model_used="",
                requires_human_review=True
            )
    
    def _get_moderation_prompt(self, content_type: str, config: ModerationConfiguration) -> str:
        """Get appropriate moderation prompt for content type."""
        custom_prompts = config.custom_rules.get("prompts", {}) if config.custom_rules else {}
        
        if content_type in custom_prompts:
            return custom_prompts[content_type]
        
        return self.default_prompts.get(content_type, self.default_prompts["default"])
    
    def _get_default_prompts(self) -> Dict[str, str]:
        """Get default moderation prompts for different content types."""
        return {
            "default": """
You are a content moderation AI. Analyze the following content and provide a moderation decision.

Respond with a JSON object containing:
- confidence: float (0.0-1.0) - your confidence in the decision
- action: string - one of: approve, reject, flag, warn, delete
- severity: string - one of: low, medium, high, critical
- reasoning: string - explanation of your decision
- categories: array of strings - categories of issues found (if any)

Consider these factors:
- Hate speech, harassment, or bullying
- Spam or promotional content
- Violence or threats
- Adult content or inappropriate material
- Misinformation or harmful content
- Privacy violations

Be balanced and consider context. Err on the side of human review for borderline cases.
""",
            
            "message": """
You are moderating a chat message. Look for:
- Inappropriate language or harassment
- Spam or repetitive content
- Threats or violence
- Personal information sharing
- Off-topic or disruptive content

Respond with JSON format as specified.
""",
            
            "file": """
You are moderating a file upload. Consider:
- File name appropriateness
- Potential malware or security risks
- Copyright or intellectual property issues
- Inappropriate content based on file type
- File size and format compliance

Respond with JSON format as specified.
""",
            
            "username": """
You are moderating a username. Check for:
- Inappropriate or offensive terms
- Impersonation attempts
- Spam or promotional usernames
- Confusing or misleading names
- Policy violations

Respond with JSON format as specified.
"""
        }
    
    def _requires_human_review(self, result: ModerationResult, config: ModerationConfiguration) -> bool:
        """Determine if human review is required."""
        # Always require human review if configured
        if config.require_human_review_for_ai:
            return True
        
        # Require review for low confidence
        if result.confidence_score < config.escalation_threshold:
            return True
        
        # Require review for high severity actions
        if result.severity in [ModerationSeverity.HIGH, ModerationSeverity.CRITICAL]:
            return True
        
        # Require review for certain actions
        if result.recommended_action in [ModerationAction.BAN, ModerationAction.DELETE]:
            return True
        
        return False
    
    def _get_provider_for_config(self, config: ModerationConfiguration) -> Optional[str]:
        """Get provider name for configuration."""
        # This would typically look up the configured provider
        # For now, return the first available provider
        return list(self.providers.keys())[0] if self.providers else None
    
    async def _check_rate_limit(self, provider_name: str, config: ModerationConfiguration) -> bool:
        """Check if rate limit allows this request."""
        now = time.time()
        minute_key = int(now // 60)
        
        if provider_name not in self.rate_limits:
            self.rate_limits[provider_name] = {}
        
        provider_limits = self.rate_limits[provider_name]
        
        if minute_key not in provider_limits:
            provider_limits[minute_key] = 0
        
        # Clean old entries
        for key in list(provider_limits.keys()):
            if key < minute_key - 5:  # Keep last 5 minutes
                del provider_limits[key]
        
        if provider_limits[minute_key] >= config.max_requests_per_minute:
            return False
        
        provider_limits[minute_key] += 1
        return True
    
    async def _test_provider(self, config: AIProviderConfig) -> bool:
        """Test if provider is working correctly."""
        try:
            test_request = await self._prepare_moderation_request(
                "This is a test message",
                "message",
                config,
                None,
                None
            )
            
            response = await self._call_ai_provider(config, test_request)
            return response is not None
            
        except Exception as e:
            logger.error(f"Provider test failed: {e}")
            return False
    
    def _decrypt_api_key(self, api_key_hash: str) -> str:
        """Decrypt API key from hash (placeholder implementation)."""
        # In production, this would properly decrypt the stored API key
        # For now, return the hash as-is (assuming it's the actual key)
        return api_key_hash
    
    def _fill_request_template(
        self,
        template: Dict[str, Any],
        content: str,
        prompt: str,
        metadata: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Fill request template with actual values."""
        # Simple template filling - in production this would be more sophisticated
        request = template.copy()
        
        def replace_placeholders(obj):
            if isinstance(obj, str):
                return obj.replace("{content}", content).replace("{prompt}", prompt)
            elif isinstance(obj, dict):
                return {k: replace_placeholders(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [replace_placeholders(item) for item in obj]
            return obj
        
        return replace_placeholders(request)
    
    def _parse_custom_response(
        self,
        response: Dict[str, Any],
        response_format: Dict[str, Any]
    ) -> ModerationResult:
        """Parse custom provider response format."""
        # Extract values based on response format configuration
        confidence = response.get(response_format.get("confidence_field", "confidence"), 0.5)
        action = response.get(response_format.get("action_field", "action"), "flag")
        reasoning = response.get(response_format.get("reasoning_field", "reasoning"), "No reasoning provided")
        
        return ModerationResult(
            confidence_score=float(confidence),
            recommended_action=ModerationAction(action),
            reasoning=reasoning,
            severity=ModerationSeverity.MEDIUM,
            categories=[],
            metadata=response,
            processing_time_ms=0,
            model_used="custom",
            requires_human_review=False
        )


# Global service instance
ai_moderation_service = AIModerationService()
