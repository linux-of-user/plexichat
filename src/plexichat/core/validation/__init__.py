# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""PlexiChat Validation"""

import logging
from typing import Any, Dict

try:
    from .validator import (  # type: ignore
        Validator, BaseValidator, ValidationResult, ValidationError,
        StringValidator, IntegerValidator, EmailValidator, DateTimeValidator,
        ListValidator, DictValidator,
        validator, validate_data, validate_data_async, validate_schema, validate_schema_async,
        string_validator, integer_validator, email_validator, datetime_validator,
        list_validator, dict_validator
    )
    logger = logging.getLogger(__name__)
    logger.info("Validation modules imported")
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Could not import validation modules: {e}")

__all__ = [
    "Validator",
    "BaseValidator",
    "ValidationResult",
    "ValidationError",
    "StringValidator",
    "IntegerValidator",
    "EmailValidator",
    "DateTimeValidator",
    "ListValidator",
    "DictValidator",
    "validator",
    "validate_data",
    "validate_data_async",
    "validate_schema",
    "validate_schema_async",
    "string_validator",
    "integer_validator",
    "email_validator",
    "datetime_validator",
    "list_validator",
    "dict_validator",
]

__version__ = "1.0.0"
