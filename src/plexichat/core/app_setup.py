import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

logger = logging.getLogger(__name__)

from plexichat.core.plugins.manager import plugin_manager


def setup_routers(app: FastAPI):
    """Setup API routers with error handling, including dynamic plugin routers."""
    # --- Core Routers ---
    core_routers = {
        "web": ("plexichat.interfaces.web.routers.web", "/web"),
        "auth": ("plexichat.interfaces.web.routers.auth", "/auth"),
        "help": ("plexichat.interfaces.web.routers.help", "/help"),
        "api_v1": ("plexichat.interfaces.api.v1.router", ""),
        "admin": ("plexichat.interfaces.web.routers.admin", "/admin"),
        "easter_eggs": ("plexichat.interfaces.api.routers.easter_eggs", None),
    }

    for name, (module_path, prefix) in core_routers.items():
        try:
            module = __import__(module_path, fromlist=["router"])
            router = (
                getattr(module, "router", None)
                or getattr(module, "v1_router", None)
                or getattr(module, "root_router", None)
            )
            if router:
                app.include_router(router, prefix=prefix, tags=[name])
                logger.info(f"[CHECK] Core router '{name}' loaded.")
            else:
                logger.warning(f"Could not find a router in module {module_path}")
        except ImportError as e:
            logger.warning(f"Core router '{name}' not available: {e}")

    # --- Plugin Routers ---
    logger.info("Loading plugin routers...")
    try:
        plugin_routers = plugin_manager.get_all_plugin_routers()
        if not plugin_routers:
            logger.info("No plugin routers found to load.")
        else:
            for plugin_name, router_info in plugin_routers.items():
                for prefix, router in router_info.items():
                    try:
                        app.include_router(
                            router, prefix=prefix, tags=[f"plugin: {plugin_name}"]
                        )
                        logger.info(
                            f"[CHECK] Plugin router loaded for '{plugin_name}' at prefix '{prefix}'."
                        )
                    except Exception as e:
                        logger.error(
                            f"Failed to include router from plugin '{plugin_name}' at prefix '{prefix}': {e}"
                        )
    except Exception as e:
        logger.error(f"Failed to get plugin routers from manager: {e}", exc_info=True)


def setup_static_files(app: FastAPI):
    """Setup static files and templates."""
    try:
        # Get project root and construct paths
        project_root = Path(__file__).parent.parent.parent.parent

        # Static files
        static_path = project_root / "src/plexichat/interfaces/web/static"
        if static_path.exists():
            app.mount("/static", StaticFiles(directory=str(static_path)), name="static")
            logger.info("[CHECK] Static files mounted")

        # Templates
        templates_path = project_root / "src/plexichat/interfaces/web/templates"
        if templates_path.exists():
            templates = Jinja2Templates(directory=str(templates_path))
            logger.info("[CHECK] Templates loaded")
            return templates

    except Exception as e:
        logger.warning(f"Could not setup static files/templates: {e}")

    return None
