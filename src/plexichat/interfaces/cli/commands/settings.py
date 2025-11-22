"""
PlexiChat Settings Management CLI Commands

Provides comprehensive CLI commands for managing system settings, user settings,
and client settings with support for viewing, updating, validation, bulk operations,
and configuration export/import.
"""

import asyncio
from datetime import datetime
import json
from pathlib import Path
import sys
from typing import Any

import click
import yaml

# Import configuration and client settings service
try:
    from plexichat.core.config_manager import get_config, get_config_manager
    from plexichat.infrastructure.services.client_settings_service import (
        RateLimitError,
        SettingType,
        StorageLimitError,
        ValidationError,
        client_settings_service,
    )
except ImportError:
    # Mock implementations for standalone execution
    class MockConfigManager:
        def get(self, key: str, default: Any = None) -> Any:
            return default

        def set(self, key: str, value: Any) -> None:
            pass

        def save(self) -> None:
            pass

        def load(self) -> None:
            pass

        @property
        def _config(self):
            return type("MockConfig", (), {})()

    class MockClientSettingsService:
        async def get_user_settings(
            self, user_id: str, user_permissions: set[str] | None = None
        ) -> list[dict[str, Any]]:
            return []

        async def get_setting(
            self, user_id: str, key: str, user_permissions: set[str] | None = None
        ) -> dict[str, Any] | None:
            return None

        async def set_setting(
            self,
            user_id: str,
            key: str,
            value: Any,
            setting_type: str = "string",
            user_permissions: set[str] | None = None,
        ) -> dict[str, Any]:
            return {
                "setting_key": key,
                "setting_value": value,
                "updated_at": datetime.utcnow(),
            }

        async def delete_setting(
            self, user_id: str, key: str, user_permissions: set[str] | None = None
        ) -> bool:
            return True

        async def bulk_update_settings(
            self,
            user_id: str,
            settings: dict[str, Any],
            user_permissions: set[str] | None = None,
        ) -> dict[str, Any]:
            return {"updated_count": len(settings)}

        async def get_user_stats(
            self, user_id: str, user_permissions: set[str] | None = None
        ) -> dict[str, Any]:
            return {"total_settings": 0, "total_storage_bytes": 0}

        async def get_user_images(
            self, user_id: str, user_permissions: set[str] | None = None
        ) -> list[dict[str, Any]]:
            return []

    def get_config_manager():
        return MockConfigManager()

    def get_config(key: str, default: Any = None) -> Any:
        return default

    client_settings_service = MockClientSettingsService()


@click.group()
def settings():
    """PlexiChat Settings Management Commands."""
    pass


# System Settings Commands
@settings.group()
def system():
    """System configuration management."""
    pass


@system.command()
@click.option(
    "--section", "-s", help="Configuration section to view (e.g., network, security)"
)
@click.option("--key", "-k", help="Specific configuration key to view")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "yaml", "table"]),
    default="table",
    help="Output format",
)
def view(section: str | None, key: str | None, output_format: str):
    """View system configuration settings."""
    try:
        config_manager = get_config_manager()

        if key:
            # View specific key
            value = config_manager.get(key)
            if value is None:
                click.echo(f"Configuration key '{key}' not found.", err=True)
                return

            if output_format == "json":
                click.echo(json.dumps({key: value}, indent=2))
            elif output_format == "yaml":
                click.echo(yaml.dump({key: value}, default_flow_style=False))
            else:
                click.echo(f"{key}: {value}")

        elif section:
            # View specific section
            try:
                section_config = getattr(config_manager._config, section)
                section_dict = (
                    section_config.__dict__
                    if hasattr(section_config, "__dict__")
                    else {}
                )

                if output_format == "json":
                    click.echo(json.dumps(section_dict, indent=2, default=str))
                elif output_format == "yaml":
                    click.echo(yaml.dump(section_dict, default_flow_style=False))
                else:
                    click.echo(f"[{section}]")
                    for k, v in section_dict.items():
                        # Mask sensitive values
                        if (
                            "password" in k.lower()
                            or "secret" in k.lower()
                            or "key" in k.lower()
                        ):
                            v = "***MASKED***"
                        click.echo(f"  {k}: {v}")
            except AttributeError:
                click.echo(f"Configuration section '{section}' not found.", err=True)

        else:
            # View all sections
            config = config_manager._config
            all_sections = {}

            for attr_name in dir(config):
                if not attr_name.startswith("_"):
                    attr_value = getattr(config, attr_name)
                    if hasattr(attr_value, "__dict__"):
                        section_dict = attr_value.__dict__.copy()
                        # Mask sensitive values
                        for k, v in section_dict.items():
                            if (
                                "password" in k.lower()
                                or "secret" in k.lower()
                                or "key" in k.lower()
                            ):
                                section_dict[k] = "***MASKED***"
                        all_sections[attr_name] = section_dict

            if output_format == "json":
                click.echo(json.dumps(all_sections, indent=2, default=str))
            elif output_format == "yaml":
                click.echo(yaml.dump(all_sections, default_flow_style=False))
            else:
                for section_name, section_data in all_sections.items():
                    click.echo(f"[{section_name}]")
                    for k, v in section_data.items():
                        click.echo(f"  {k}: {v}")
                    click.echo()

    except Exception as e:
        click.echo(f"Error viewing configuration: {e}", err=True)
        sys.exit(1)


@system.command()
@click.argument("key")
@click.argument("value")
@click.option(
    "--type",
    "value_type",
    type=click.Choice(["string", "int", "float", "bool", "json"]),
    default="string",
    help="Value type",
)
@click.option("--save", is_flag=True, help="Save configuration to file after setting")
def set(key: str, value: str, value_type: str, save: bool):
    """Set a system configuration value."""
    try:
        config_manager = get_config_manager()

        # Convert value based on type
        if value_type == "int":
            converted_value = int(value)
        elif value_type == "float":
            converted_value = float(value)
        elif value_type == "bool":
            converted_value = value.lower() in ("true", "1", "yes", "on")
        elif value_type == "json":
            converted_value = json.loads(value)
        else:
            converted_value = value

        config_manager.set(key, converted_value)

        if save:
            config_manager.save()
            click.echo(
                f"Configuration key '{key}' set to '{converted_value}' and saved."
            )
        else:
            click.echo(
                f"Configuration key '{key}' set to '{converted_value}' (not saved to file)."
            )

    except (ValueError, json.JSONDecodeError) as e:
        click.echo(f"Error converting value: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error setting configuration: {e}", err=True)
        sys.exit(1)


@system.command()
@click.option(
    "--validate-only", is_flag=True, help="Only validate configuration without saving"
)
def validate(validate_only: bool):
    """Validate system configuration."""
    try:
        config_manager = get_config_manager()
        config = config_manager._config

        errors = []
        warnings = []

        # Basic validation checks
        # Network configuration
        if hasattr(config, "network"):
            network = config.network
            if hasattr(network, "port") and (network.port < 1 or network.port > 65535):
                errors.append("network.port must be between 1 and 65535")

            if hasattr(network, "ssl_enabled") and network.ssl_enabled:
                if (
                    hasattr(network, "ssl_cert_path")
                    and not Path(network.ssl_cert_path).exists()
                ):
                    errors.append(
                        f"SSL certificate file not found: {network.ssl_cert_path}"
                    )
                if (
                    hasattr(network, "ssl_key_path")
                    and not Path(network.ssl_key_path).exists()
                ):
                    errors.append(f"SSL key file not found: {network.ssl_key_path}")

        # Security configuration
        if hasattr(config, "security"):
            security = config.security
            if hasattr(security, "secret_key") and security.secret_key == "change-me":
                warnings.append(
                    "security.secret_key is using default value - should be changed"
                )
            if (
                hasattr(security, "jwt_secret")
                and security.jwt_secret == "change-me-too"
            ):
                warnings.append(
                    "security.jwt_secret is using default value - should be changed"
                )

        # Database configuration
        if hasattr(config, "database"):
            database = config.database
            if hasattr(database, "type") and database.type == "sqlite":
                if hasattr(database, "path"):
                    db_path = Path(database.path)
                    if not db_path.parent.exists():
                        warnings.append(
                            f"Database directory does not exist: {db_path.parent}"
                        )

        # Report results
        if errors:
            click.echo("Configuration Errors:", err=True)
            for error in errors:
                click.echo(f"  [ERROR] {error}", err=True)

        if warnings:
            click.echo("Configuration Warnings:")
            for warning in warnings:
                click.echo(f"  [WARNING] {warning}")

        if not errors and not warnings:
            click.echo("[OK] Configuration is valid.")

        if errors:
            sys.exit(1)

    except Exception as e:
        click.echo(f"Error validating configuration: {e}", err=True)
        sys.exit(1)


@system.command()
@click.argument("output_file", type=click.Path())
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "yaml"]),
    default="yaml",
    help="Export format",
)
@click.option(
    "--include-sensitive",
    is_flag=True,
    help="Include sensitive values (use with caution)",
)
def export(output_file: str, output_format: str, include_sensitive: bool):
    """Export system configuration to file."""
    try:
        config_manager = get_config_manager()
        config = config_manager._config

        # Convert config to dictionary
        config_dict = {}
        for attr_name in dir(config):
            if not attr_name.startswith("_"):
                attr_value = getattr(config, attr_name)
                if hasattr(attr_value, "__dict__"):
                    section_dict = attr_value.__dict__.copy()

                    # Mask sensitive values unless explicitly requested
                    if not include_sensitive:
                        for k, v in section_dict.items():
                            if (
                                "password" in k.lower()
                                or "secret" in k.lower()
                                or "key" in k.lower()
                            ):
                                section_dict[k] = "***MASKED***"

                    config_dict[attr_name] = section_dict

        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            if output_format == "json":
                json.dump(config_dict, f, indent=2, default=str)
            else:
                yaml.dump(config_dict, f, default_flow_style=False)

        click.echo(f"Configuration exported to {output_path}")

        if not include_sensitive:
            click.echo(
                "Note: Sensitive values were masked. Use --include-sensitive to export actual values."
            )

    except Exception as e:
        click.echo(f"Error exporting configuration: {e}", err=True)
        sys.exit(1)


@system.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "--merge",
    is_flag=True,
    help="Merge with existing configuration instead of replacing",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be imported without actually doing it",
)
def import_config(input_file: str, merge: bool, dry_run: bool):
    """Import system configuration from file."""
    try:
        config_manager = get_config_manager()
        input_path = Path(input_file)

        # Load configuration from file
        with open(input_path, encoding="utf-8") as f:
            if input_path.suffix.lower() == ".json":
                imported_config = json.load(f)
            else:
                imported_config = yaml.safe_load(f)

        if dry_run:
            click.echo("Dry run - showing what would be imported:")
            click.echo(yaml.dump(imported_config, default_flow_style=False))
            return

        if not merge:
            # Replace entire configuration
            if click.confirm("This will replace your entire configuration. Continue?"):
                # Update configuration sections
                for section_name, section_data in imported_config.items():
                    if hasattr(config_manager._config, section_name):
                        section = getattr(config_manager._config, section_name)
                        for key, value in section_data.items():
                            if hasattr(section, key):
                                setattr(section, key, value)

                config_manager.save()
                click.echo("Configuration imported and saved.")
            else:
                click.echo("Import cancelled.")
        else:
            # Merge with existing configuration
            for section_name, section_data in imported_config.items():
                if hasattr(config_manager._config, section_name):
                    section = getattr(config_manager._config, section_name)
                    for key, value in section_data.items():
                        if hasattr(section, key):
                            setattr(section, key, value)

            config_manager.save()
            click.echo("Configuration merged and saved.")

    except Exception as e:
        click.echo(f"Error importing configuration: {e}", err=True)
        sys.exit(1)


@system.command()
def reload():
    """Reload system configuration from file."""
    try:
        config_manager = get_config_manager()
        config_manager.load()
        click.echo("Configuration reloaded from file.")
    except Exception as e:
        click.echo(f"Error reloading configuration: {e}", err=True)
        sys.exit(1)


@system.command()
def save():
    """Save current system configuration to file."""
    try:
        config_manager = get_config_manager()
        config_manager.save()
        click.echo("Configuration saved to file.")
    except Exception as e:
        click.echo(f"Error saving configuration: {e}", err=True)
        sys.exit(1)


# Client Settings Commands
@settings.group()
def client():
    """Client settings management."""
    pass


@client.command()
@click.argument("user_id")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "yaml", "table"]),
    default="table",
    help="Output format",
)
@click.option(
    "--type-filter",
    help="Filter by setting type (string, integer, float, boolean, json, image, binary)",
)
def list_settings(user_id: str, output_format: str, type_filter: str | None):
    """List all settings for a user."""

    async def _list_settings():
        try:
            settings = await client_settings_service.get_user_settings(user_id)

            if type_filter:
                settings = [s for s in settings if s.get("setting_type") == type_filter]

            if not settings:
                click.echo(f"No settings found for user '{user_id}'.")
                return

            if output_format == "json":
                click.echo(json.dumps(settings, indent=2, default=str))
            elif output_format == "yaml":
                click.echo(yaml.dump(settings, default_flow_style=False))
            else:
                click.echo(f"Settings for user '{user_id}':")
                click.echo("-" * 60)
                for setting in settings:
                    key = setting["setting_key"]
                    value = setting["setting_value"]
                    setting_type = setting["setting_type"]
                    updated = setting.get("updated_at", "Unknown")
                    size = setting.get("size_bytes", 0)

                    # Truncate long values for table display
                    if isinstance(value, str) and len(value) > 50:
                        value = value[:47] + "..."
                    elif isinstance(value, dict):
                        value = f"<{setting_type} object>"

                    click.echo(f"  {key} ({setting_type}): {value}")
                    click.echo(f"    Updated: {updated}, Size: {size} bytes")
                    click.echo()

        except Exception as e:
            click.echo(f"Error listing settings: {e}", err=True)
            sys.exit(1)

    asyncio.run(_list_settings())


@client.command()
@click.argument("user_id")
@click.argument("key")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "yaml", "raw"]),
    default="raw",
    help="Output format",
)
def get(user_id: str, key: str, output_format: str):
    """Get a specific setting for a user."""

    async def _get_setting():
        try:
            setting = await client_settings_service.get_setting(user_id, key)

            if not setting:
                click.echo(f"Setting '{key}' not found for user '{user_id}'.", err=True)
                sys.exit(1)

            if output_format == "json":
                click.echo(json.dumps(setting, indent=2, default=str))
            elif output_format == "yaml":
                click.echo(yaml.dump(setting, default_flow_style=False))
            else:
                value = setting["setting_value"]
                if setting["setting_type"] in ["image", "binary"]:
                    click.echo(
                        f"<{setting['setting_type']} data - {setting.get('size_bytes', 0)} bytes>"
                    )
                else:
                    click.echo(value)

        except Exception as e:
            click.echo(f"Error getting setting: {e}", err=True)
            sys.exit(1)

    asyncio.run(_get_setting())


@client.command()
@click.argument("user_id")
@click.argument("key")
@click.argument("value")
@click.option(
    "--type",
    "setting_type",
    type=click.Choice(["string", "integer", "float", "boolean", "json"]),
    default="string",
    help="Setting type",
)
def set_setting(user_id: str, key: str, value: str, setting_type: str):
    """Set a setting for a user."""

    async def _set_setting():
        try:
            # Convert value based on type
            if setting_type == "integer":
                converted_value = int(value)
            elif setting_type == "float":
                converted_value = float(value)
            elif setting_type == "boolean":
                converted_value = value.lower() in ("true", "1", "yes", "on")
            elif setting_type == "json":
                converted_value = json.loads(value)
            else:
                converted_value = value

            result = await client_settings_service.set_setting(
                user_id, key, converted_value, setting_type
            )
            click.echo(f"Setting '{key}' set for user '{user_id}'.")
            click.echo(f"Value: {result['setting_value']}")
            click.echo(f"Type: {result['setting_type']}")
            click.echo(f"Size: {result.get('size_bytes', 0)} bytes")

        except (ValueError, json.JSONDecodeError) as e:
            click.echo(f"Error converting value: {e}", err=True)
            sys.exit(1)
        except (ValidationError, RateLimitError, StorageLimitError) as e:
            click.echo(f"Error setting value: {e}", err=True)
            sys.exit(1)
        except Exception as e:
            click.echo(f"Unexpected error: {e}", err=True)
            sys.exit(1)

    asyncio.run(_set_setting())


@client.command()
@click.argument("user_id")
@click.argument("key")
@click.argument("image_path", type=click.Path(exists=True))
def set_image(user_id: str, key: str, image_path: str):
    """Set an image setting for a user."""

    async def _set_image():
        try:
            import base64
            import mimetypes

            path = Path(image_path)

            # Detect content type
            content_type, _ = mimetypes.guess_type(str(path))
            if not content_type or not content_type.startswith("image/"):
                click.echo(f"File does not appear to be an image: {path}", err=True)
                sys.exit(1)

            # Read and encode image
            with open(path, "rb") as f:
                image_data = f.read()

            image_value = {
                "data": base64.b64encode(image_data).decode("utf-8"),
                "content_type": content_type,
            }

            result = await client_settings_service.set_setting(
                user_id, key, image_value, "image"
            )
            click.echo(f"Image setting '{key}' set for user '{user_id}'.")
            click.echo(f"Content type: {content_type}")
            click.echo(f"Size: {result.get('size_bytes', 0)} bytes")

        except (ValidationError, RateLimitError, StorageLimitError) as e:
            click.echo(f"Error setting image: {e}", err=True)
            sys.exit(1)
        except Exception as e:
            click.echo(f"Unexpected error: {e}", err=True)
            sys.exit(1)

    asyncio.run(_set_image())


@client.command()
@click.argument("user_id")
@click.argument("key")
@click.confirmation_option(prompt="Are you sure you want to delete this setting?")
def delete(user_id: str, key: str):
    """Delete a setting for a user."""

    async def _delete_setting():
        try:
            success = await client_settings_service.delete_setting(user_id, key)
            if success:
                click.echo(f"Setting '{key}' deleted for user '{user_id}'.")
            else:
                click.echo(f"Setting '{key}' not found for user '{user_id}'.", err=True)
                sys.exit(1)

        except Exception as e:
            click.echo(f"Error deleting setting: {e}", err=True)
            sys.exit(1)

    asyncio.run(_delete_setting())


@client.command()
@click.argument("user_id")
@click.argument("settings_file", type=click.Path(exists=True))
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be imported without actually doing it",
)
def bulk_import(user_id: str, settings_file: str, dry_run: bool):
    """Bulk import settings for a user from JSON/YAML file."""

    async def _bulk_import():
        try:
            path = Path(settings_file)

            with open(path, encoding="utf-8") as f:
                if path.suffix.lower() == ".json":
                    settings = json.load(f)
                else:
                    settings = yaml.safe_load(f)

            if not isinstance(settings, dict):
                click.echo("Settings file must contain a dictionary/object.", err=True)
                sys.exit(1)

            if dry_run:
                click.echo(f"Dry run - would import {len(settings)} settings:")
                for key, value in settings.items():
                    click.echo(f"  {key}: {value}")
                return

            result = await client_settings_service.bulk_update_settings(
                user_id, settings
            )

            click.echo(f"Bulk import completed for user '{user_id}'.")
            click.echo(f"Updated: {result['updated_count']} settings")

            if "errors" in result:
                click.echo(f"Errors: {len(result['errors'])}")
                for error in result["errors"]:
                    click.echo(f"  {error['key']}: {error['error']}", err=True)

        except (ValidationError, RateLimitError, StorageLimitError) as e:
            click.echo(f"Error during bulk import: {e}", err=True)
            sys.exit(1)
        except Exception as e:
            click.echo(f"Unexpected error: {e}", err=True)
            sys.exit(1)

    asyncio.run(_bulk_import())


@client.command()
@click.argument("user_id")
@click.argument("output_file", type=click.Path())
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "yaml"]),
    default="json",
    help="Export format",
)
@click.option(
    "--include-images",
    is_flag=True,
    help="Include image data in export (may result in large files)",
)
def export_settings(
    user_id: str, output_file: str, output_format: str, include_images: bool
):
    """Export all settings for a user to a file."""

    async def _export_settings():
        try:
            settings = await client_settings_service.get_user_settings(user_id)

            if not settings:
                click.echo(f"No settings found for user '{user_id}'.")
                return

            # Convert to export format
            export_data = {}
            for setting in settings:
                key = setting["setting_key"]
                value = setting["setting_value"]
                setting_type = setting["setting_type"]

                # Skip images unless explicitly requested
                if setting_type in ["image", "binary"] and not include_images:
                    export_data[key] = f"<{setting_type} data - excluded from export>"
                else:
                    export_data[key] = value

            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, "w", encoding="utf-8") as f:
                if output_format == "json":
                    json.dump(export_data, f, indent=2, default=str)
                else:
                    yaml.dump(export_data, f, default_flow_style=False)

            click.echo(f"Settings exported to {output_path}")
            click.echo(f"Exported {len(export_data)} settings")

            if not include_images:
                image_count = sum(
                    1 for s in settings if s["setting_type"] in ["image", "binary"]
                )
                if image_count > 0:
                    click.echo(
                        f"Note: {image_count} image/binary settings were excluded. Use --include-images to export them."
                    )

        except Exception as e:
            click.echo(f"Error exporting settings: {e}", err=True)
            sys.exit(1)

    asyncio.run(_export_settings())


@client.command()
@click.argument("user_id")
def stats(user_id: str):
    """Show storage statistics for a user."""

    async def _show_stats():
        try:
            stats = await client_settings_service.get_user_stats(user_id)

            click.echo(f"Storage statistics for user '{user_id}':")
            click.echo("-" * 40)
            click.echo(f"Total settings: {stats.get('total_settings', 0)}")
            click.echo(f"Total storage: {stats.get('total_storage_bytes', 0)} bytes")
            click.echo(f"Image settings: {stats.get('image_count', 0)}")
            click.echo(f"Binary settings: {stats.get('binary_count', 0)}")
            click.echo(f"Storage limit: {stats.get('storage_limit_bytes', 0)} bytes")
            click.echo(f"Settings limit: {stats.get('settings_limit', 0)}")

            # Calculate usage percentages
            storage_used = stats.get("total_storage_bytes", 0)
            storage_limit = stats.get("storage_limit_bytes", 1)
            storage_percent = (storage_used / storage_limit) * 100

            settings_used = stats.get("total_settings", 0)
            settings_limit = stats.get("settings_limit", 1)
            settings_percent = (settings_used / settings_limit) * 100

            click.echo(f"Storage usage: {storage_percent:.1f}%")
            click.echo(f"Settings usage: {settings_percent:.1f}%")

        except Exception as e:
            click.echo(f"Error getting statistics: {e}", err=True)
            sys.exit(1)

    asyncio.run(_show_stats())


@client.command()
@click.argument("user_id")
def list_images(user_id: str):
    """List all image settings for a user."""

    async def _list_images():
        try:
            images = await client_settings_service.get_user_images(user_id)

            if not images:
                click.echo(f"No image settings found for user '{user_id}'.")
                return

            click.echo(f"Image settings for user '{user_id}':")
            click.echo("-" * 60)

            for image in images:
                key = image["setting_key"]
                content_type = image.get("content_type", "unknown")
                size = image.get("size", 0)
                updated = image.get("updated_at", "Unknown")
                hash_value = image.get("hash", "Unknown")

                click.echo(f"  {key}")
                click.echo(f"    Type: {content_type}")
                click.echo(f"    Size: {size} bytes")
                click.echo(f"    Updated: {updated}")
                click.echo(f"    Hash: {hash_value}")
                click.echo()

        except Exception as e:
            click.echo(f"Error listing images: {e}", err=True)
            sys.exit(1)

    asyncio.run(_list_images())


# User Settings Commands (for managing user-specific application settings)
@settings.group()
def user():
    """User-specific application settings."""
    pass


@user.command()
@click.argument("user_id")
@click.option("--category", help="Setting category (ui, notifications, privacy, etc.)")
def preferences(user_id: str, category: str | None):
    """View user preferences and application settings."""

    async def _show_preferences():
        try:
            # Get user settings that are application preferences
            settings = await client_settings_service.get_user_settings(user_id)

            # Filter by category if specified
            if category:
                settings = [
                    s for s in settings if s["setting_key"].startswith(f"{category}.")
                ]

            # Group by category
            categories = {}
            for setting in settings:
                key = setting["setting_key"]
                if "." in key:
                    cat, subkey = key.split(".", 1)
                else:
                    cat, subkey = "general", key

                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(
                    {
                        "key": subkey,
                        "value": setting["setting_value"],
                        "type": setting["setting_type"],
                    }
                )

            if not categories:
                click.echo(f"No preferences found for user '{user_id}'.")
                return

            click.echo(f"User preferences for '{user_id}':")
            click.echo("=" * 50)

            for cat_name, cat_settings in categories.items():
                click.echo(f"\n[{cat_name}]")
                for setting in cat_settings:
                    click.echo(
                        f"  {setting['key']}: {setting['value']} ({setting['type']})"
                    )

        except Exception as e:
            click.echo(f"Error showing preferences: {e}", err=True)
            sys.exit(1)

    asyncio.run(_show_preferences())


@user.command()
@click.argument("user_id")
@click.argument("preference_key")
@click.argument("value")
@click.option("--category", default="general", help="Preference category")
def set_preference(user_id: str, preference_key: str, value: str, category: str):
    """Set a user preference."""

    async def _set_preference():
        try:
            # Construct full key with category
            full_key = f"{category}.{preference_key}"

            # Try to infer type from value
            if value.lower() in ("true", "false"):
                converted_value = value.lower() == "true"
                setting_type = "boolean"
            elif value.isdigit():
                converted_value = int(value)
                setting_type = "integer"
            elif "." in value and value.replace(".", "").isdigit():
                converted_value = float(value)
                setting_type = "float"
            else:
                converted_value = value
                setting_type = "string"

            result = await client_settings_service.set_setting(
                user_id, full_key, converted_value, setting_type
            )
            click.echo(
                f"Preference '{preference_key}' set in category '{category}' for user '{user_id}'."
            )
            click.echo(f"Value: {result['setting_value']} ({result['setting_type']})")

        except Exception as e:
            click.echo(f"Error setting preference: {e}", err=True)
            sys.exit(1)

    asyncio.run(_set_preference())


if __name__ == "__main__":
    settings()
