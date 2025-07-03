#!/usr/bin/env python3
"""
NetLink AI CLI Tool
Command-line interface for managing AI providers and models.
"""

import asyncio
import json
import sys
import argparse
from pathlib import Path
from typing import List, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from netlink.ai.core.ai_abstraction_layer import (
    AIAbstractionLayer, AIRequest, AIModel, AIProvider, 
    ModelCapability, ModelStatus
)

class AICommandLineInterface:
    """Command-line interface for AI management."""
    
    def __init__(self):
        self.ai_layer = AIAbstractionLayer()
        
    async def list_models(self, provider: Optional[str] = None, status: Optional[str] = None):
        """List AI models."""
        models = list(self.ai_layer.models.values())
        
        if provider:
            models = [m for m in models if m.provider == provider]
        if status:
            models = [m for m in models if m.status == status]
            
        if not models:
            print("No models found matching criteria.")
            return
            
        print(f"\n{'ID':<20} {'Name':<25} {'Provider':<15} {'Status':<12} {'Priority':<8}")
        print("-" * 85)
        
        for model in sorted(models, key=lambda m: m.priority):
            print(f"{model.id:<20} {model.name:<25} {model.provider:<15} {model.status.value:<12} {model.priority:<8}")
            
    async def list_providers(self):
        """List AI providers."""
        print(f"\n{'Provider':<15} {'Enabled':<8} {'Has API Key':<12} {'Base URL':<30}")
        print("-" * 70)
        
        for provider, config in self.ai_layer.providers.items():
            enabled = "Yes" if config.get("enabled", False) else "No"
            has_key = "Yes" if config.get("api_key_encrypted") else "No"
            base_url = config.get("base_url", "")[:28] + "..." if len(config.get("base_url", "")) > 30 else config.get("base_url", "")
            
            print(f"{provider:<15} {enabled:<8} {has_key:<12} {base_url:<30}")
            
    async def health_check(self):
        """Perform health check."""
        health = await self.ai_layer.health_check()
        
        print(f"\n🏥 AI System Health Check")
        print(f"Overall Status: {health['overall_status'].upper()}")
        print(f"Total Models: {health['total_models']}")
        print(f"Available Models: {health['available_models']}")
        print(f"Unavailable Models: {health['unavailable_models']}")
        
        print(f"\n📊 Provider Status:")
        for provider, stats in health['providers'].items():
            print(f"  {provider}: {stats['available']}/{stats['total']} available")
            
        print(f"\n🧠 Model Health:")
        for model_id, model_info in health['models'].items():
            health_info = model_info.get('health', {})
            total_requests = health_info.get('total_requests', 0)
            success_rate = 0
            if total_requests > 0:
                success_rate = (health_info.get('successful_requests', 0) / total_requests) * 100
                
            print(f"  {model_id}: {model_info['status']} (Success: {success_rate:.1f}%, Requests: {total_requests})")
            
    async def test_model(self, model_id: str, prompt: str, user_id: str = "cli_user"):
        """Test AI model with a prompt."""
        print(f"\n🧪 Testing model: {model_id}")
        print(f"Prompt: {prompt}")
        print("-" * 50)
        
        request = AIRequest(
            user_id=user_id,
            model_id=model_id,
            prompt=prompt,
            max_tokens=100,
            temperature=0.7
        )
        
        try:
            response = await self.ai_layer.process_request(request)
            
            if response.success:
                print(f"✅ Success!")
                print(f"Response: {response.content}")
                print(f"Latency: {response.latency_ms}ms")
                print(f"Cost: ${response.cost:.6f}")
                print(f"Provider: {response.provider}")
                if response.fallback_used:
                    print(f"⚠️ Fallback used: {response.fallback_model}")
                if response.cached:
                    print("📦 Response was cached")
            else:
                print(f"❌ Failed: {response.error}")
                
        except Exception as e:
            print(f"❌ Error: {e}")
            
    async def configure_provider(self, provider: str, api_key: str, base_url: str = "", enabled: bool = True):
        """Configure AI provider."""
        config = {
            "api_key": api_key,
            "enabled": enabled
        }
        
        if base_url:
            config["base_url"] = base_url
            
        try:
            success = await self.ai_layer.configure_provider(AIProvider(provider), config)
            if success:
                print(f"✅ Provider {provider} configured successfully")
            else:
                print(f"❌ Failed to configure provider {provider}")
        except Exception as e:
            print(f"❌ Error configuring provider: {e}")
            
    async def add_model(self, model_data: dict):
        """Add new AI model."""
        try:
            model = AIModel(
                id=model_data["id"],
                name=model_data["name"],
                provider=AIProvider(model_data["provider"]),
                capabilities=[ModelCapability(cap) for cap in model_data["capabilities"]],
                max_tokens=model_data["max_tokens"],
                cost_per_1k_tokens=model_data["cost_per_1k_tokens"],
                context_window=model_data["context_window"],
                priority=model_data.get("priority", 1)
            )
            
            success = await self.ai_layer.add_model(model)
            if success:
                print(f"✅ Model {model.id} added successfully")
            else:
                print(f"❌ Failed to add model {model.id}")
                
        except Exception as e:
            print(f"❌ Error adding model: {e}")
            
    async def remove_model(self, model_id: str):
        """Remove AI model."""
        try:
            success = await self.ai_layer.remove_model(model_id)
            if success:
                print(f"✅ Model {model_id} removed successfully")
            else:
                print(f"❌ Model {model_id} not found")
        except Exception as e:
            print(f"❌ Error removing model: {e}")
            
    def clear_cache(self):
        """Clear AI cache."""
        self.ai_layer.clear_cache()
        print("✅ AI cache cleared")
        
    async def get_usage_stats(self, user_id: Optional[str] = None):
        """Get usage statistics."""
        if user_id:
            stats = self.ai_layer.get_usage_stats(user_id)
            if not stats:
                print(f"No usage data found for user: {user_id}")
                return
                
            print(f"\n📊 Usage Statistics for {user_id}:")
            for model_id, usage in stats.items():
                print(f"  {model_id}:")
                print(f"    Total Tokens: {usage['total_tokens']}")
                print(f"    Total Cost: ${usage['total_cost']:.6f}")
                print(f"    Requests: {usage['request_count']}")
                print(f"    Last Request: {usage['last_request']}")
        else:
            all_stats = self.ai_layer.get_usage_stats()
            print(f"\n📊 System Usage Statistics:")
            print(f"Total Users: {len(all_stats)}")
            
            total_tokens = 0
            total_cost = 0.0
            total_requests = 0
            
            for user_id, user_stats in all_stats.items():
                for model_id, usage in user_stats.items():
                    total_tokens += usage['total_tokens']
                    total_cost += usage['total_cost']
                    total_requests += usage['request_count']
                    
            print(f"Total Tokens: {total_tokens}")
            print(f"Total Cost: ${total_cost:.6f}")
            print(f"Total Requests: {total_requests}")

async def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(description="NetLink AI Management CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # List models command
    list_models_parser = subparsers.add_parser("list-models", help="List AI models")
    list_models_parser.add_argument("--provider", help="Filter by provider")
    list_models_parser.add_argument("--status", help="Filter by status")
    
    # List providers command
    subparsers.add_parser("list-providers", help="List AI providers")
    
    # Health check command
    subparsers.add_parser("health", help="Perform health check")
    
    # Test model command
    test_parser = subparsers.add_parser("test", help="Test AI model")
    test_parser.add_argument("model_id", help="Model ID to test")
    test_parser.add_argument("prompt", help="Test prompt")
    test_parser.add_argument("--user-id", default="cli_user", help="User ID for test")
    
    # Configure provider command
    config_parser = subparsers.add_parser("configure", help="Configure AI provider")
    config_parser.add_argument("provider", help="Provider name")
    config_parser.add_argument("api_key", help="API key")
    config_parser.add_argument("--base-url", help="Base URL")
    config_parser.add_argument("--disabled", action="store_true", help="Disable provider")
    
    # Add model command
    add_parser = subparsers.add_parser("add-model", help="Add AI model")
    add_parser.add_argument("config_file", help="JSON config file for model")
    
    # Remove model command
    remove_parser = subparsers.add_parser("remove-model", help="Remove AI model")
    remove_parser.add_argument("model_id", help="Model ID to remove")
    
    # Clear cache command
    subparsers.add_parser("clear-cache", help="Clear AI cache")
    
    # Usage stats command
    usage_parser = subparsers.add_parser("usage", help="Get usage statistics")
    usage_parser.add_argument("--user-id", help="Specific user ID")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
        
    cli = AICommandLineInterface()
    
    try:
        if args.command == "list-models":
            await cli.list_models(args.provider, args.status)
        elif args.command == "list-providers":
            await cli.list_providers()
        elif args.command == "health":
            await cli.health_check()
        elif args.command == "test":
            await cli.test_model(args.model_id, args.prompt, args.user_id)
        elif args.command == "configure":
            await cli.configure_provider(args.provider, args.api_key, 
                                       args.base_url or "", not args.disabled)
        elif args.command == "add-model":
            with open(args.config_file, 'r') as f:
                model_data = json.load(f)
            await cli.add_model(model_data)
        elif args.command == "remove-model":
            await cli.remove_model(args.model_id)
        elif args.command == "clear-cache":
            cli.clear_cache()
        elif args.command == "usage":
            await cli.get_usage_stats(args.user_id)
            
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
