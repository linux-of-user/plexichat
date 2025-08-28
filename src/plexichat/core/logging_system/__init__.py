try:
    # Prefer the new unified logging system
    from plexichat.core.logging_unified import (
        setup_logging,
        get_logger,
        get_directory_manager,
    )
except Exception:
    # Fall back to the legacy logger to maintain backward compatibility
    try:
        from plexichat.core.logging.logger import (
            setup_logging,
            get_logger,
            get_directory_manager,
        )
    except Exception:
        # If the legacy logger doesn't provide get_directory_manager, provide a graceful stub.
        from plexichat.core.logging.logger import setup_logging, get_logger

        def get_directory_manager(*args, **kwargs):
            """
            Compatibility stub for get_directory_manager when neither the unified logging
            system nor the legacy logger expose it. Returns None to indicate the feature
            is unavailable in this environment.
            """
            return None


__all__ = ["setup_logging", "get_logger", "get_directory_manager"]