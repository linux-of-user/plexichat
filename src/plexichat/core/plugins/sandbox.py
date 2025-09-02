import sys
import pathlib
import yaml

# Find repo root
repo_root = pathlib.Path(__file__).parents[5]
config_path = repo_root / 'allowed_imports.yaml'

with open(config_path, 'r') as f:
    data = yaml.safe_load(f)

allowed_modules = set(data['allowed_modules'])

class WhitelistFinder:
    def find_spec(self, fullname, path, target=None):
        allowed = any(
            fullname == mod or fullname.startswith(mod + '.') or mod.startswith(fullname + '.')
            for mod in allowed_modules
        )
        if not allowed:
            raise ImportError(f"Import of '{fullname}' is not allowed by the whitelist.")
        return None

# Install the finder
sys.meta_path.insert(0, WhitelistFinder())