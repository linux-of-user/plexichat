# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Optional

import tabulate


from plexichat.ai.core.ai_abstraction_layer import (  # !/usr/bin/env python3; Add parent directory to path for imports)

    AI,
    CLI,
    Command-line,
    Path,
    PlexiChat,
    ProviderStatus,
    Tool,
    0,
    """,
    .parent.parent.parent,
    __file__,
    and,
    for,
    from,
    import,
    interface,
    managing,
    models.,
    pathlib,
    plexichat.ai.providers,
    providers,
    str,
    sys.path.insert,
)

    AIAbstractionLayer,
    AIModel,
    AIProvider,
    AIRequest,
    ModelCapability,
)
logger = logging.getLogger(__name__)

logger = logging.getLogger(__name__)
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
            logger.info("No models found matching criteria.")
            return

        logger.info(f"\n{'ID':<20} {'Name':<25} {'Provider':<15} {'Status':<12} {'Priority':<8}")
        logger.info("-" * 85)

        for model in sorted(models, key=lambda m: m.priority):
            logger.info(f"{model.id:<20} {model.name:<25} {model.provider:<15} {model.status.value:<12} {model.priority:<8}")

    async def list_providers(self):
        """List AI providers with enhanced status information."""
        try:
            provider_status = await self.ai_layer.get_provider_status()
            provider_configs = self.ai_layer.providers

            headers = ["Provider", "Enabled", "Status", "Models", "Health", "Base URL"]
            rows = []

            for provider_type in AIProvider:
                config = provider_configs.get(provider_type, {})
                status = provider_status.get(provider_type, {})

                health_info = status.get("health", {})
                health_str = "Unknown"
                if health_info:
                    if "error" in health_info:
                        health_str = f"Error: {health_info['error'][:20]}..."
                    else:
                        health_str = "Healthy"

                base_url = config.get("base_url", "")
                if len(base_url) > 25:
                    base_url = base_url[:22] + "..."

                rows.append([)
                    provider_type.value,
                    "Yes" if config.get("enabled", False) else "No",
                    status.get("status", ProviderStatus.UNAVAILABLE).value,
                    len(status.get("models", [])),
                    health_str,
                    base_url
                ])

            logger.info("\nAI Providers:")
            logger.info(tabulate.tabulate(rows, headers=headers, tablefmt="grid"))

        except Exception as e:
            logger.info(f"Error listing providers: {e}")
            return 1

        return 0

    async def configure_provider_advanced(self, provider_name: str, **kwargs):
        """Configure an AI provider (advanced)."""
        try:
            provider = AIProvider(provider_name)

            # Get current config
            current_config = self.ai_layer.providers.get(provider, {})

            # Build new config
            config = current_config.copy()

            for key, value in kwargs.items():
                if value is not None:
                    config[key.replace('_', '-')] = value

            success = await self.ai_layer.configure_provider(provider, config)

            if success:
                logger.info(f" Provider {provider.value} configured successfully")

                # Refresh provider instance
                await self.ai_layer.refresh_provider(provider)
                logger.info(f" Provider {provider.value} refreshed")

                return 0
            else:
                logger.info(f" Failed to configure provider {provider.value}")
                return 1

        except ValueError:
            logger.info(f"Error: Invalid provider '{provider_name}'. Valid providers: {[p.value for p in AIProvider]}")
            return 1
        except Exception as e:
            logger.info(f"Error configuring provider: {e}")
            return 1

    async def ollama_models(self, action: str, model_id: Optional[str] = None):
        """Manage Ollama models."""
        try:
            if action == "list":
                models = await self.ai_layer.discover_ollama_models()
                logger.info(f"\nAvailable Ollama Models ({len(models)} total):")
                for model in models:
                    logger.info(f"   {model}")

            elif action == "pull":
                if not model_id:
                    logger.info("Error: model_id required for pull action")
                    return 1

                logger.info(f"Pulling Ollama model: {model_id}")
                success = await self.ai_layer.pull_ollama_model(model_id)

                if success:
                    logger.info(f" Successfully pulled model: {model_id}")
                    return 0
                else:
                    logger.info(f" Failed to pull model: {model_id}")
                    return 1

            elif action == "delete":
                if not model_id:
                    logger.info("Error: model_id required for delete action")
                    return 1

                success = await self.ai_layer.delete_ollama_model(model_id)

                if success:
                    logger.info(f" Successfully deleted model: {model_id}")
                    return 0
                else:
                    logger.info(f" Failed to delete model: {model_id}")
                    return 1

            return 0

        except Exception as e:
            logger.info(f"Error managing Ollama models: {e}")
            return 1

    async def show_stats(self, verbose: bool = False):
        """Show AI system statistics."""
        try:
            usage_stats = self.ai_layer.get_usage_stats()

            logger.info("\nAI System Statistics")
            logger.info(f"Total Models: {len(self.ai_layer.models)}")
            logger.info(f"Total Providers: {len(self.ai_layer.providers)}")
            logger.info(f"Active Providers: {len(self.ai_layer.provider_instances)}")
            logger.info(f"Request Cache Size: {len(self.ai_layer.request_cache)}")
            logger.info(f"Request History: {len(self.ai_layer.request_history)}")
            logger.info(f"Response History: {len(self.ai_layer.response_history)}")

            if verbose and usage_stats:
                logger.info("\nUser Usage Statistics:")
                for user_id, user_stats in usage_stats.items():
                    logger.info(f"  User: {user_id}")
                    total_tokens = sum(model_stats.get('total_tokens', 0) for model_stats in user_stats.values())
                    total_cost = sum(model_stats.get('total_cost', 0) for model_stats in user_stats.values())
                    total_requests = sum(model_stats.get('request_count', 0) for model_stats in user_stats.values())
                    logger.info(f"    Total Requests: {total_requests}")
                    logger.info(f"    Total Tokens: {total_tokens:,}")
                    logger.info(f"    Total Cost: ${total_cost:.4f}")

            return 0

        except Exception as e:
            logger.info(f"Error showing statistics: {e}")
            return 1

    async def health_check(self):
        """Perform health check."""
        health = await self.ai_layer.health_check()

        logger.info("\n AI System Health Check")
        logger.info(f"Overall Status: {health['overall_status'].upper()}")
        logger.info(f"Total Models: {health['total_models']}")
        logger.info(f"Available Models: {health['available_models']}")
        logger.info(f"Unavailable Models: {health['unavailable_models']}")

        logger.info("\n Provider Status:")
        for provider, stats in health['providers'].items():
            logger.info(f"  {provider}: {stats['available']}/{stats['total']} available")

        logger.info("\n Model Health:")
        for model_id, model_info in health['models'].items():
            health_info = model_info.get('health', {})
            total_requests = health_info.get('total_requests', 0)
            success_rate = 0
            if total_requests > 0:
                success_rate = (health_info.get('successful_requests', 0) / total_requests) * 100

            logger.info(f"  {model_id}: {model_info['status']} (Success: {success_rate:.1f}%, Requests: {total_requests})")

    async def test_model(self, model_id: str, prompt: str, user_id: str = "cli_user"):
        """Test AI model with a prompt."""
        logger.info(f"\n Testing model: {model_id}")
        logger.info(f"Prompt: {prompt}")
        logger.info("-" * 50)

        request = AIRequest()
            user_id=user_id,
            model_id=model_id,
            prompt=prompt,
            max_tokens=100,
            temperature=0.7
        )

        try:
            response = await self.ai_layer.process_request(request)

            if response.success:
                logger.info(" Success!")
                logger.info(f"Response: {response.content}")
                logger.info(f"Latency: {response.latency_ms}ms")
                logger.info(f"Cost: ${response.cost:.6f}")
                logger.info(f"Provider: {response.provider}")
                if response.fallback_used:
                    logger.info(f" Fallback used: {response.fallback_model}")
                if response.cached:
                    logger.info(" Response was cached")
            else:
                logger.info(f" Failed: {response.error}")

        except Exception as e:
            logger.info(f" Error: {e}")

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
                logger.info(f" Provider {provider} configured successfully")
            else:
                logger.info(f" Failed to configure provider {provider}")
        except Exception as e:
            logger.info(f" Error configuring provider: {e}")

    async def add_model(self, model_data: dict):
        """Add new AI model."""
        try:
            model = AIModel()
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
                logger.info(f" Model {model.id} added successfully")
            else:
                logger.info(f" Failed to add model {model.id}")

        except Exception as e:
            logger.info(f" Error adding model: {e}")

    async def remove_model(self, model_id: str):
        """Remove AI model."""
        try:
            success = await self.ai_layer.remove_model(model_id)
            if success:
                logger.info(f" Model {model_id} removed successfully")
            else:
                logger.info(f" Model {model_id} not found")
        except Exception as e:
            logger.info(f" Error removing model: {e}")

    def clear_cache(self):
        """Clear AI cache."""
        self.ai_layer.clear_cache()
        logger.info(" AI cache cleared")

    async def get_usage_stats(self, user_id: Optional[str] = None):
        """Get usage statistics."""
        if user_id:
            stats = self.ai_layer.get_usage_stats(user_id)
            if not stats:
                logger.info(f"No usage data found for user: {user_id}")
                return

            logger.info(f"\n Usage Statistics for {user_id}:")
            for model_id, usage in stats.items():
                logger.info(f"  {model_id}:")
                logger.info(f"    Total Tokens: {usage['total_tokens']}")
                logger.info(f"    Total Cost: ${usage['total_cost']:.6f}")
                logger.info(f"    Requests: {usage['request_count']}")
                logger.info(f"    Last Request: {usage['last_request']}")
        else:
            all_stats = self.ai_layer.get_usage_stats()
            logger.info("\n System Usage Statistics:")
            logger.info(f"Total Users: {len(all_stats)}")

            total_tokens = 0
            total_cost = 0.0
            total_requests = 0

            for user_id, user_stats in all_stats.items():
                for model_id, usage in user_stats.items():
                    total_tokens += usage['total_tokens']
                    total_cost += usage['total_cost']
                    total_requests += usage['request_count']

            logger.info(f"Total Tokens: {total_tokens}")
            logger.info(f"Total Cost: ${total_cost:.6f}")
            logger.info(f"Total Requests: {total_requests}")

async def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(description="PlexiChat AI Management CLI")
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
            await cli.configure_provider(args.provider, args.api_key,)
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
        logger.info("\n Goodbye!")
    except Exception as e:
        logger.info(f" Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
