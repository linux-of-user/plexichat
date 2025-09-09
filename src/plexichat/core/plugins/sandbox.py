import logging
import pathlib
import sys

import yaml

# Find repo root
repo_root = pathlib.Path(__file__).parents[5]
config_path = repo_root / "allowed_imports.yaml"

with open(config_path, "r") as f:
    data = yaml.safe_load(f)

allowed_modules = set(data.get("allowed_modules", []))
exceptions = set(data.get("exceptions", []))


class WhitelistFinder:
    def find_spec(self, fullname, path, target=None):
        allowed = any(
            fullname == mod
            or fullname.startswith(mod + ".")
            or mod.startswith(fullname + ".")
            for mod in allowed_modules
        )
        if not allowed:
            if fullname in exceptions:
                logging.warning(
                    f"Import of '{fullname}' is forbidden but approved via exceptions."
                )
                return None
            else:
                logging.warning(
                    f"Import of '{fullname}' is forbidden and not approved."
                )
                raise ImportError(
                    f"Import of '{fullname}' is not allowed by the whitelist."
                )
        return None


# Install the finder
sys.meta_path.insert(0, WhitelistFinder())
