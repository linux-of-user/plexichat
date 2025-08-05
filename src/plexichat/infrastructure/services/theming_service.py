# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


from pathlib import Path


from pathlib import Path

from plexichat.app.logger_config import logger

"""
import time
Advanced theming service for PlexiChat.
Provides comprehensive theming capabilities across all interfaces.
"""

@dataclass
class ThemeColors:
    """Theme color configuration."""
    primary: str = "#2c3e50"
    secondary: str = "#3498db"
    success: str = "#27ae60"
    warning: str = "#f39c12"
    danger: str = "#e74c3c"
    info: str = "#9b59b6"
    dark: str = "#1a1a1a"
    light: str = "#ffffff"
    background: str = "#f8f9fa"
    surface: str = "#ffffff"
    text_primary: str = "#2c3e50"
    text_secondary: str = "#7f8c8d"
    border: str = "#dee2e6"
    shadow: str = "rgba(0,0,0,0.1)"


@dataclass
class ThemeLayout:
    """Theme layout configuration."""
    sidebar_width: str = "280px"
    header_height: str = "60px"
    border_radius: str = "8px"
    spacing_unit: str = "16px"
    font_family: str = "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif"
    font_size_base: str = "14px"
    line_height: str = "1.5"
    container_max_width: str = "1200px"


@dataclass
class ThemeEffects:
    """Theme visual effects configuration."""
    animations_enabled: bool = True
    transitions_duration: str = "0.3s"
    box_shadow_enabled: bool = True
    gradient_enabled: bool = True
    blur_enabled: bool = True
    hover_effects: bool = True
    focus_effects: bool = True


@dataclass
class Theme:
    """Complete theme configuration."""
    id: str
    name: str
    description: str
    colors: ThemeColors
    layout: ThemeLayout
    effects: ThemeEffects
    is_dark: bool = False
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def __post_init__(self):
        if not self.created_at:
created_at = datetime().now().isoformat()
updated_at = datetime().now().isoformat()


class ThemingService:
    """Advanced theming service."""

    def __init__(self):
        from pathlib import Path
self.themes_directory = Path("data/themes")
        self.themes_directory.mkdir(parents=True, exist_ok=True)

        self.user_preferences_file = self.themes_directory / "user_preferences.json"
        self.custom_themes_file = self.themes_directory / "custom_themes.json"

        self.built_in_themes = self._create_built_in_themes()
        self.custom_themes = self._load_custom_themes()
        self.user_preferences = self._load_user_preferences()

    def _create_built_in_themes(self) -> Dict[str, Theme]:
        """Create built-in themes."""
        themes = {}

        # Default Light Theme
        themes["default_light"] = Theme()
            id="default_light",
            name="Default Light",
            description="Clean and modern light theme",
            colors=ThemeColors(),
            layout=ThemeLayout(),
            effects=ThemeEffects(),
            is_dark=False
        )

        # Dark Theme
        themes["dark"] = Theme()
            id="dark",
            name="Dark Professional",
            description="Professional dark theme for extended use",
            colors=ThemeColors()
                primary="#2c3e50",
                secondary="#3498db",
                success="#27ae60",
                warning="#f39c12",
                danger="#e74c3c",
                info="#9b59b6",
                dark="#1a1a1a",
                light="#ffffff",
                background="#1e1e1e",
                surface="#2d2d2d",
                text_primary="#e0e0e0",
                text_secondary="#b0b0b0",
                border="#444444",
                shadow="rgba(0,0,0,0.3)"
            ),
            layout=ThemeLayout(),
            effects=ThemeEffects(),
            is_dark=True
        )

        # Blue Theme
        themes["blue"] = Theme()
            id="blue",
            name="Ocean Blue",
            description="Calming blue-themed interface",
            colors=ThemeColors()
                primary="#1e3a8a",
                secondary="#3b82f6",
                success="#10b981",
                warning="#f59e0b",
                danger="#ef4444",
                info="#8b5cf6",
                background="#f0f9ff",
                surface="#ffffff",
                text_primary="#1e3a8a",
                text_secondary="#64748b"
            ),
            layout=ThemeLayout(),
            effects=ThemeEffects(),
            is_dark=False
        )

        # Purple Theme
        themes["purple"] = Theme()
            id="purple",
            name="Royal Purple",
            description="Elegant purple theme with modern aesthetics",
            colors=ThemeColors()
                primary="#7c3aed",
                secondary="#a855f7",
                success="#10b981",
                warning="#f59e0b",
                danger="#ef4444",
                info="#06b6d4",
                background="#faf5ff",
                surface="#ffffff",
                text_primary="#581c87",
                text_secondary="#64748b"
            ),
            layout=ThemeLayout(),
            effects=ThemeEffects(),
            is_dark=False
        )

        # Green Theme
        themes["green"] = Theme()
            id="green",
            name="Nature Green",
            description="Fresh green theme inspired by nature",
            colors=ThemeColors()
                primary="#166534",
                secondary="#22c55e",
                success="#10b981",
                warning="#f59e0b",
                danger="#ef4444",
                info="#06b6d4",
                background="#f0fdf4",
                surface="#ffffff",
                text_primary="#166534",
                text_secondary="#64748b"
            ),
            layout=ThemeLayout(),
            effects=ThemeEffects(),
            is_dark=False
        )

        # High Contrast Theme
        themes["high_contrast"] = Theme()
            id="high_contrast",
            name="High Contrast",
            description="High contrast theme for accessibility",
            colors=ThemeColors()
                primary="#000000",
                secondary="#0066cc",
                success="#008000",
                warning="#ff8c00",
                danger="#ff0000",
                info="#800080",
                background="#ffffff",
                surface="#ffffff",
                text_primary="#000000",
                text_secondary="#333333",
                border="#000000"
            ),
            layout=ThemeLayout()
                border_radius="4px",
                font_size_base="16px"
            ),
            effects=ThemeEffects()
                animations_enabled=False,
                box_shadow_enabled=False,
                gradient_enabled=False,
                blur_enabled=False
            ),
            is_dark=False
        )

        # Cyberpunk Theme
        themes["cyberpunk"] = Theme()
            id="cyberpunk",
            name="Cyberpunk",
            description="Futuristic cyberpunk-inspired theme",
            colors=ThemeColors()
                primary="#ff00ff",
                secondary="#00ffff",
                success="#00ff00",
                warning="#ffff00",
                danger="#ff0040",
                info="#8000ff",
                dark="#0a0a0a",
                background="#0d1117",
                surface="#161b22",
                text_primary="#00ffff",
                text_secondary="#7d8590",
                border="#30363d",
                shadow="rgba(255,0,255,0.3)"
            ),
            layout=ThemeLayout()
                font_family="'Courier New', monospace",
                border_radius="2px"
            ),
            effects=ThemeEffects()
                gradient_enabled=True,
                blur_enabled=True
            ),
            is_dark=True
        )

        return themes

    def _load_custom_themes(self) -> Dict[str, Theme]:
        """Load custom themes from file."""
        try:
            if self.custom_themes_file.exists() if self.custom_themes_file else False:
                with open(self.custom_themes_file, 'r') as f:
                    data = json.load(f)
                    return {
                        theme_id: Theme(**theme_data)
                        for theme_id, theme_data in data.items()
                    }
        except Exception as e:
            logger.error(f"Failed to load custom themes: {e}")

        return {}

    def _save_custom_themes(self):
        """Save custom themes to file."""
        try:
            data = {
                theme_id: asdict(theme)
                for theme_id, theme in self.custom_themes.items()
            }

            with open(self.custom_themes_file, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            logger.error(f"Failed to save custom themes: {e}")

    def _load_user_preferences(self) -> Dict[str, Any]:
        """Load user theme preferences."""
        try:
            if self.user_preferences_file.exists() if self.user_preferences_file else False:
                with open(self.user_preferences_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load user preferences: {e}")

        return {}
            "default_theme": "default_light",
            "user_themes": {},
            "auto_dark_mode": False,
            "dark_mode_schedule": {
                "enabled": False,
                "start_time": "18:00",
                "end_time": "06:00"
            }
        }

    def _save_user_preferences(self):
        """Save user theme preferences."""
        try:
            with open(self.user_preferences_file, 'w') as f:
                json.dump(self.user_preferences, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save user preferences: {e}")

    def get_all_themes(self) -> Dict[str, Theme]:
        """Get all available themes."""
        all_themes = {}
        all_themes.update(self.built_in_themes)
        all_themes.update(self.custom_themes)
        return all_themes

    def get_theme(self, theme_id: str) -> Optional[Theme]:
        """Get a specific theme by ID."""
        all_themes = self.get_all_themes()
        return all_themes.get(theme_id)

    def get_theme_list(self) -> List[Dict[str, Any]]:
        """Get list of themes with metadata."""
        themes = []

        for theme_id, theme in self.get_all_themes().items():
            themes.append({)
                "id": theme.id,
                "name": theme.name,
                "description": theme.description,
                "is_dark": theme.is_dark,
                "is_custom": theme_id in self.custom_themes,
                "created_at": theme.created_at,
                "updated_at": theme.updated_at
            })

        return sorted(themes, key=lambda x: (x["is_custom"], x["name"]))

    def create_custom_theme():
        self,
        name: str,
        description: str,
        base_theme_id: str = "default_light",
        colors: Optional[Dict[str, str]] = None,
        layout: Optional[Dict[str, str]] = None,
        effects: Optional[Dict[str, Any]] = None
    ) -> Theme:
        """Create a new custom theme."""

        # Get base theme
        base_theme = self.get_theme(base_theme_id)
        if not base_theme:
            base_theme = self.built_in_themes["default_light"]

        # Generate unique ID
        theme_id = f"custom_{name.lower().replace(' ', '_')}_{int(from datetime import datetime)
datetime.now().timestamp())}"

        # Create theme colors
        theme_colors = ThemeColors(**asdict(base_theme.colors))
        if colors:
            for key, value in colors.items():
                if hasattr(theme_colors, key):
                    setattr(theme_colors, key, value)

        # Create theme layout
        theme_layout = ThemeLayout(**asdict(base_theme.layout))
        if layout:
            for key, value in layout.items():
                if hasattr(theme_layout, key):
                    setattr(theme_layout, key, value)

        # Create theme effects
        theme_effects = ThemeEffects(**asdict(base_theme.effects))
        if effects:
            for key, value in effects.items():
                if hasattr(theme_effects, key):
                    setattr(theme_effects, key, value)

        # Create new theme
        new_theme = Theme()
            id=theme_id,
            name=name,
            description=description,
            colors=theme_colors,
            layout=theme_layout,
            effects=theme_effects,
            is_dark=base_theme.is_dark
        )

        # Save to custom themes
        self.custom_themes[theme_id] = new_theme
        self._save_custom_themes()

        logger.info(f"Created custom theme: {name} ({theme_id})")
        return new_theme

    def update_custom_theme(self, theme_id: str, updates: Dict[str, Any]) -> bool:
        """Update a custom theme."""
        if theme_id not in self.custom_themes:
            return False

        theme = self.custom_themes[theme_id]

        # Update theme properties
        for key, value in updates.items():
            if hasattr(theme, key):
                setattr(theme, key, value)

        theme.from datetime import datetime
updated_at = datetime().now().isoformat()

        self._save_custom_themes()
        logger.info(f"Updated custom theme: {theme_id}")
        return True

    def delete_custom_theme(self, theme_id: str) -> bool:
        """Delete a custom theme."""
        if theme_id not in self.custom_themes:
            return False

        del self.custom_themes[theme_id]
        self._save_custom_themes()

        logger.info(f"Deleted custom theme: {theme_id}")
        return True

    def set_user_theme(self, user_id: int, theme_id: str) -> bool:
        """Set theme for a specific user."""
        if not self.get_theme(theme_id):
            return False

        self.user_preferences["user_themes"][str(user_id)] = theme_id
        self._save_user_preferences()

        logger.info(f"Set theme {theme_id} for user {user_id}")
        return True

    def get_user_theme(self, user_id: int) -> str:
        """Get theme for a specific user."""
        user_theme = self.user_preferences["user_themes"].get(str(user_id))
        if user_theme and self.get_theme(user_theme):
            return user_theme

        return self.user_preferences["default_theme"]

    def generate_css(self, theme_id: str) -> str:
        """Generate CSS for a theme."""
        theme = self.get_theme(theme_id)
        if not theme:
            theme = self.built_in_themes["default_light"]

        css = f"""
/* PlexiChat Theme: {theme.name} */
:root {{
    /* Colors */
    --primary-color: {theme.colors.primary};
    --secondary-color: {theme.colors.secondary};
    --success-color: {theme.colors.success};
    --warning-color: {theme.colors.warning};
    --danger-color: {theme.colors.danger};
    --info-color: {theme.colors.info};
    --dark-color: {theme.colors.dark};
    --light-color: {theme.colors.light};
    --background-color: {theme.colors.background};
    --surface-color: {theme.colors.surface};
    --text-primary: {theme.colors.text_primary};
    --text-secondary: {theme.colors.text_secondary};
    --border-color: {theme.colors.border};
    --shadow-color: {theme.colors.shadow};

    /* Layout */
    --sidebar-width: {theme.layout.sidebar_width};
    --header-height: {theme.layout.header_height};
    --border-radius: {theme.layout.border_radius};
    --spacing-unit: {theme.layout.spacing_unit};
    --font-family: {theme.layout.font_family};
    --font-size-base: {theme.layout.font_size_base};
    --line-height: {theme.layout.line_height};
    --container-max-width: {theme.layout.container_max_width};

    /* Effects */
    --transition-duration: {theme.effects.transitions_duration};
}}

/* Base styles */
body {{
    font-family: var(--font-family);
    font-size: var(--font-size-base);
    line-height: var(--line-height);
    color: var(--text-primary);
    background-color: var(--background-color);
    {"transition: all var(--transition-duration) ease;" if theme.effects.animations_enabled else ""}
}}

/* Component styles */
.btn {{
    border-radius: var(--border-radius);
    {"transition: all var(--transition-duration) ease;" if theme.effects.animations_enabled else ""}
    {"box-shadow: 0 2px 4px var(--shadow-color);" if theme.effects.box_shadow_enabled else ""}
}}

.card {{
    background-color: var(--surface-color);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    {"box-shadow: 0 4px 6px var(--shadow-color);" if theme.effects.box_shadow_enabled else ""}
}}

.btn:hover {{
    {"transform: translateY(-2px);" if theme.effects.hover_effects else ""}
    {"box-shadow: 0 4px 8px var(--shadow-color);" if theme.effects.box_shadow_enabled and theme.effects.hover_effects else ""}
}}

/* Animations */
{"@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }" if theme.effects.animations_enabled else ""}
{".fade-in { animation: fadeIn var(--transition-duration) ease; }" if theme.effects.animations_enabled else ""}

/* Dark theme adjustments */
{"" if not theme.is_dark else """
.dark-theme {
    color-scheme: dark;
}

.dark-theme input,
.dark-theme textarea,
.dark-theme select {
    background-color: var(--surface-color);
    color: var(--text-primary);
    border-color: var(--border-color);
}

.dark-theme input:focus,
.dark-theme textarea:focus,
.dark-theme select:focus {
    border-color: var(--secondary-color);
    box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.1);
}
"""}
        """

        return css.strip()

    def export_theme(self, theme_id: str) -> Optional[Dict[str, Any]]:
        """Export a theme as JSON."""
        theme = self.get_theme(theme_id)
        if not theme:
            return None

        return asdict(theme)

    def import_theme(self, theme_data: Dict[str, Any]) -> Optional[Theme]:
        """Import a theme from JSON data."""
        try:
            # Validate required fields
            required_fields = ["id", "name", "description", "colors", "layout", "effects"]
            if not all(field in theme_data for field in required_fields):
                return None

            # Create theme object
            theme = Theme()
                id=theme_data["id"],
                name=theme_data["name"],
                description=theme_data["description"],
                colors=ThemeColors(**theme_data["colors"]),
                layout=ThemeLayout(**theme_data["layout"]),
                effects=ThemeEffects(**theme_data["effects"]),
                is_dark=theme_data.get("is_dark", False)
            )

            # Add to custom themes
            self.custom_themes[theme.id] = theme
            self._save_custom_themes()

            logger.info(f"Imported theme: {theme.name} ({theme.id})")
            return theme

        except Exception as e:
            logger.error(f"Failed to import theme: {e}")
            return None


# Global theming service instance
theming_service = ThemingService()
