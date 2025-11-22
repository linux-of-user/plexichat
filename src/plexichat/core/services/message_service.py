optimizer.register_function(
    "plexichat.core.services.message_service", "calculate_checksum", compiler="cython"
)


class MessageService:
    """Central service that implements the shared message logic.

    This is intentionally generic so both API and Web routers can delegate
    without losing any behavior. Extend with hooks for persistence, moderation,
    encryption, etc., preserving existing features.
    """

    def __init__(self) -> None:
        self._history_enabled = True

    def format_message(self, data: dict[str, Any]) -> dict[str, Any]:
        content = str(data.get("content", ""))
        sender = data.get("sender")
        channel = data.get("channel")
        message_type = data.get("type", "text")
        flags = data.get("flags", []) or []
        msg = Message(
            content=content,
            sender=sender,
            channel=channel,
            message_type=message_type,
            flags=flags,
        )
        result = {
            "content": msg.content,
            "sender": msg.sender,
            "channel": msg.channel,
            "type": msg.message_type,
            "flags": msg.flags,
            "checksum": msg.checksum(),
        }
        logger.debug("Formatted message: %s", result)
        return result

    async def save_if_enabled(self, formatted: dict[str, Any]) -> None:
        if not self._history_enabled:
            return
        # Hook for persistence; safe no-op default to avoid feature loss
        try:
            # e.g., await message_repository.save(formatted)
            logger.debug(
                "Persisting message (noop hook): %s", formatted.get("checksum")
            )
        except Exception as e:
            logger.warning("Message persistence hook failed: %s", e)

    def enable_history(self, enabled: bool) -> None:
        self._history_enabled = enabled


# Singleton-like shared instance
message_service = MessageService()
