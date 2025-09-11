"""
PlexiChat Message Formatter

Handles rich text formatting for messages with markdown-like syntax.
Provides parsing, rendering, and sanitization for secure message display.
"""

import html
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class FormatType(Enum):
    """Types of formatting supported."""

    BOLD = "bold"
    ITALIC = "italic"
    CODE = "code"
    CODE_BLOCK = "code_block"
    LINK = "link"
    MENTION = "mention"
    TEXT = "text"


@dataclass
class FormatElement:
    """Represents a formatted element in a message."""

    type: FormatType
    content: str
    metadata: Optional[Dict[str, Any]] = None


class MessageFormatter:
    """
    Handles parsing and rendering of rich text messages with markdown-like syntax.

    Supported syntax:
    - **bold text** or __bold text__
    - *italic text* or _italic text_
    - `inline code`
    - ```code block```
    - [link text](url)
    - @username mentions
    """

    def __init__(self):
        # Patterns for different formatting types
        self.patterns = {
            "bold": re.compile(r"\*\*(.*?)\*\*"),
            "bold_alt": re.compile(r"__(.*?)__"),
            "italic": re.compile(r"\*(.*?)\*"),
            "italic_alt": re.compile(r"_(.*?)_"),
            "code": re.compile(r"`([^`]+)`"),
            "code_block": re.compile(r"```(.*?)```", re.DOTALL),
            "link": re.compile(r"\[([^\]]+)\]\(([^)]+)\)"),
            "mention": re.compile(r"@(\w+)"),
        }

        # HTML sanitization - allowed tags and attributes
        self.allowed_tags = {"strong", "em", "code", "pre", "a", "span"}
        self.allowed_attributes = {"a": ["href", "title"], "span": ["class"]}

    def parse_message(self, content: str) -> List[FormatElement]:
        """
        Parse message content into formatted elements.

        Returns a list of FormatElement objects representing the parsed content.
        """
        if not content:
            return []

        elements = []
        remaining = content

        # Process in order of priority (most specific first)
        processors = [
            ("code_block", self._process_code_block),
            ("link", self._process_link),
            ("bold", self._process_bold),
            ("bold_alt", self._process_bold_alt),
            ("italic", self._process_italic),
            ("italic_alt", self._process_italic_alt),
            ("code", self._process_code),
            ("mention", self._process_mention),
        ]

        while remaining:
            # Find the next match
            earliest_match = None
            earliest_pos = len(remaining)
            processor_func = None

            for pattern_name, processor in processors:
                pattern = self.patterns[pattern_name]
                match = pattern.search(remaining)
                if match and match.start() < earliest_pos:
                    earliest_match = match
                    earliest_pos = match.start()
                    processor_func = processor

            if earliest_match:
                # Add any text before the match
                if earliest_pos > 0:
                    elements.append(
                        FormatElement(
                            type=FormatType.TEXT, content=remaining[:earliest_pos]
                        )
                    )

                # Process the match
                element = processor_func(earliest_match)
                if element:
                    elements.append(element)

                # Continue with remaining text
                remaining = remaining[earliest_match.end() :]
            else:
                # No more matches, add remaining text
                elements.append(FormatElement(type=FormatType.TEXT, content=remaining))
                break

        return elements

    def render_html(self, elements: List[FormatElement]) -> str:
        """
        Render formatted elements as sanitized HTML.

        Returns HTML string safe for display.
        """
        html_parts = []

        for element in elements:
            if element.type == FormatType.BOLD:
                html_parts.append(
                    f"<strong>{self._escape_html(element.content)}</strong>"
                )
            elif element.type == FormatType.ITALIC:
                html_parts.append(f"<em>{self._escape_html(element.content)}</em>")
            elif element.type == FormatType.CODE:
                html_parts.append(f"<code>{self._escape_html(element.content)}</code>")
            elif element.type == FormatType.CODE_BLOCK:
                html_parts.append(
                    f"<pre><code>{self._escape_html(element.content)}</code></pre>"
                )
            elif element.type == FormatType.LINK:
                url = element.metadata.get("url", "") if element.metadata else ""
                if self._is_safe_url(url):
                    html_parts.append(
                        f'<a href="{self._escape_html(url)}" target="_blank" rel="noopener noreferrer">{self._escape_html(element.content)}</a>'
                    )
                else:
                    html_parts.append(
                        f'<span class="invalid-link">{self._escape_html(element.content)}</span>'
                    )
            elif element.type == FormatType.MENTION:
                username = (
                    element.metadata.get("username", element.content)
                    if element.metadata
                    else element.content
                )
                html_parts.append(
                    f'<span class="mention" data-username="{self._escape_html(username)}">@{self._escape_html(element.content)}</span>'
                )
            else:  # TEXT
                html_parts.append(self._escape_html(element.content))

        return "".join(html_parts)

    def format_message(self, content: str) -> str:
        """
        Parse and render a message in one step.

        Returns sanitized HTML string.
        """
        elements = self.parse_message(content)
        return self.render_html(elements)

    def _process_bold(self, match) -> Optional[FormatElement]:
        """Process bold formatting."""
        content = match.group(1)
        if content:
            return FormatElement(type=FormatType.BOLD, content=content)
        return None

    def _process_bold_alt(self, match) -> Optional[FormatElement]:
        """Process alternative bold formatting."""
        content = match.group(1)
        if content:
            return FormatElement(type=FormatType.BOLD, content=content)
        return None

    def _process_italic(self, match) -> Optional[FormatElement]:
        """Process italic formatting."""
        content = match.group(1)
        if content:
            return FormatElement(type=FormatType.ITALIC, content=content)
        return None

    def _process_italic_alt(self, match) -> Optional[FormatElement]:
        """Process alternative italic formatting."""
        content = match.group(1)
        if content:
            return FormatElement(type=FormatType.ITALIC, content=content)
        return None

    def _process_code(self, match) -> Optional[FormatElement]:
        """Process inline code formatting."""
        content = match.group(1)
        if content:
            return FormatElement(type=FormatType.CODE, content=content)
        return None

    def _process_code_block(self, match) -> Optional[FormatElement]:
        """Process code block formatting."""
        content = match.group(1)
        if content:
            return FormatElement(type=FormatType.CODE_BLOCK, content=content)
        return None

    def _process_link(self, match) -> Optional[FormatElement]:
        """Process link formatting."""
        text = match.group(1)
        url = match.group(2)
        if text and url:
            return FormatElement(
                type=FormatType.LINK, content=text, metadata={"url": url}
            )
        return None

    def _process_mention(self, match) -> Optional[FormatElement]:
        """Process mention formatting."""
        username = match.group(1)
        if username:
            return FormatElement(
                type=FormatType.MENTION,
                content=username,
                metadata={"username": username},
            )
        return None

    def _escape_html(self, text: str) -> str:
        """Escape HTML characters for security."""
        return html.escape(text, quote=True)

    def _is_safe_url(self, url: str) -> bool:
        """
        Check if URL is safe to link to.

        Basic safety checks - in production, this should be more comprehensive.
        """
        if not url:
            return False

        # Check for dangerous protocols
        dangerous_protocols = ["javascript:", "data:", "vbscript:", "file:"]
        url_lower = url.lower()

        for protocol in dangerous_protocols:
            if url_lower.startswith(protocol):
                return False

        # Basic URL format check
        if not re.match(r"^https?://", url_lower):
            return False

        return True

    def sanitize_html(self, html_content: str) -> str:
        """
        Sanitize HTML content to prevent XSS attacks.

        This is a basic sanitizer - in production, consider using a dedicated library
        like bleach or html5lib.
        """
        # For now, we'll rely on the _escape_html method and safe URL checks
        # In a production system, implement proper HTML sanitization
        return html_content


# Global formatter instance
message_formatter = MessageFormatter()


def format_message_content(content: str) -> str:
    """Convenience function to format message content."""
    return message_formatter.format_message(content)


def parse_message_elements(content: str) -> List[FormatElement]:
    """Convenience function to parse message elements."""
    return message_formatter.parse_message(content)
