import json
from typing import Any, Dict


class ManifestValidationError(Exception):
    """Exception raised for invalid plugin manifests."""

    pass


def validate_manifest(manifest: Dict[str, Any]) -> None:
    """
    Validates a plugin manifest dictionary.

    Checks for:
    - Valid security_level (must be 'low', 'medium', or 'high')
    - Presence of dependencies (must be a list)

    Raises ManifestValidationError if validation fails.
    """
    # Validate security_level
    if "security_level" not in manifest:
        raise ManifestValidationError("Missing required field: 'security_level'")
    if manifest["security_level"] not in [
        "trusted",
        "sandboxed",
        "restricted",
        "untrusted",
    ]:
        raise ManifestValidationError(
            f"Invalid security_level: '{manifest['security_level']}'. Must be 'trusted', 'sandboxed', 'restricted', or 'untrusted'"
        )

    # Validate dependencies
    if "dependencies" not in manifest:
        raise ManifestValidationError("Missing required field: 'dependencies'")
    if not isinstance(manifest["dependencies"], list):
        raise ManifestValidationError("Invalid dependencies: must be a list")
