"""
import threading
import warnings
PlexiChat Validation System

Data validation with threading and performance optimization.
"""

import re
import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Union, Callable
from dataclasses import dataclass

try:
    from plexichat.core.threading.thread_manager import async_thread_manager
except ImportError:
    async_thread_manager = None

try:
    from plexichat.core.analytics.analytics_manager import track_event
except ImportError:
    track_event = None

try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

logger = logging.getLogger(__name__)
performance_logger = get_performance_logger() if get_performance_logger else None

@dataclass
class ValidationError:
    """Validation error information."""
    field: str
    message: str
    code: str
    value: Any

@dataclass
class ValidationResult:
    """Validation result."""
    valid: bool
    errors: List[ValidationError]
    warnings: List[ValidationError]
    cleaned_data: Dict[str, Any]

class BaseValidator(ABC):
    """Base validator class."""

    def __init__(self, required: bool = False, allow_none: bool = False):
        self.required = required
        self.allow_none = allow_none

    @abstractmethod
    def validate(self, value: Any, field_name: str = "field") -> ValidationResult:
        """Validate value."""
        pass

    def _create_error(self, field: str, message: str, code: str, value: Any) -> ValidationError:
        """Create validation error."""
        return ValidationError(field=field, message=message, code=code, value=value)

class StringValidator(BaseValidator):
    """String validator."""

    def __init__(self, min_length: Optional[int] = None, max_length: Optional[int] = None, pattern: Optional[str] = None, choices: Optional[List[str]] = None, **kwargs):
        super().__init__(**kwargs)
        self.min_length = min_length
        self.max_length = max_length
        self.pattern = re.compile(pattern) if pattern else None
        self.choices = choices

    def validate(self, value: Any, field_name: str = "field") -> ValidationResult:
        """Validate string value."""
        errors = []
        warnings = []

        # Check if value is None
        if value is None:
            if self.required:
                errors.append(self._create_error(field_name, "Field is required", "required", value))
            elif not self.allow_none:
                errors.append(self._create_error(field_name, "Field cannot be None", "null", value))
            return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings, cleaned_data={field_name: value})

        # Convert to string
        if not isinstance(value, str):
            try:
                value = str(value)
            except Exception:
                errors.append(self._create_error(field_name, "Cannot convert to string", "type", value))
                return ValidationResult(valid=False, errors=errors, warnings=warnings, cleaned_data={})

        # Check length
        if self.min_length is not None and len(value) < self.min_length:
            errors.append(self._create_error(field_name, f"Minimum length is {self.min_length}", "min_length", value))

        if self.max_length is not None and len(value) > self.max_length:
            errors.append(self._create_error(field_name, f"Maximum length is {self.max_length}", "max_length", value))

        # Check pattern
        if self.pattern and not self.pattern.match(value):
            errors.append(self._create_error(field_name, "Value does not match required pattern", "pattern", value))

        # Check choices
        if self.choices and value not in self.choices:
            errors.append(self._create_error(field_name, f"Value must be one of: {', '.join(self.choices)}", "choices", value))

        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            cleaned_data={field_name: value}
        )

class IntegerValidator(BaseValidator):
    """Integer validator."""

    def __init__(self, min_value: Optional[int] = None, max_value: Optional[int] = None, **kwargs):
        super().__init__(**kwargs)
        self.min_value = min_value
        self.max_value = max_value

    def validate(self, value: Any, field_name: str = "field") -> ValidationResult:
        """Validate integer value."""
        errors = []
        warnings = []

        # Check if value is None
        if value is None:
            if self.required:
                errors.append(self._create_error(field_name, "Field is required", "required", value))
            elif not self.allow_none:
                errors.append(self._create_error(field_name, "Field cannot be None", "null", value))
            return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings, cleaned_data={field_name: value})

        # Convert to integer
        if not isinstance(value, int):
            try:
                if isinstance(value, str):
                    value = int(value)
                elif isinstance(value, float):
                    if value.is_integer():
                        value = int(value)
                    else:
                        errors.append(self._create_error(field_name, "Value is not an integer", "type", value))
                        return ValidationResult(valid=False, errors=errors, warnings=warnings, cleaned_data={})
                else:
                    value = int(value)
            except (ValueError, TypeError):
                errors.append(self._create_error(field_name, "Cannot convert to integer", "type", value))
                return ValidationResult(valid=False, errors=errors, warnings=warnings, cleaned_data={})

        # Check range
        if self.min_value is not None and value < self.min_value:
            errors.append(self._create_error(field_name, f"Minimum value is {self.min_value}", "min_value", value))

        if self.max_value is not None and value > self.max_value:
            errors.append(self._create_error(field_name, f"Maximum value is {self.max_value}", "max_value", value))

        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            cleaned_data={field_name: value}
        )

class EmailValidator(BaseValidator):
    """Email validator."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

    def validate(self, value: Any, field_name: str = "field") -> ValidationResult:
        """Validate email value."""
        errors = []
        warnings = []

        # Check if value is None
        if value is None:
            if self.required:
                errors.append(self._create_error(field_name, "Field is required", "required", value))
            elif not self.allow_none:
                errors.append(self._create_error(field_name, "Field cannot be None", "null", value))
            return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings, cleaned_data={field_name: value})

        # Convert to string
        if not isinstance(value, str):
            try:
                value = str(value)
            except Exception:
                errors.append(self._create_error(field_name, "Cannot convert to string", "type", value))
                return ValidationResult(valid=False, errors=errors, warnings=warnings, cleaned_data={})

        # Validate email format
        if not self.email_pattern.match(value):
            errors.append(self._create_error(field_name, "Invalid email format", "email", value))

        # Check length
        if len(value) > 254:  # RFC 5321 limit
            errors.append(self._create_error(field_name, "Email address too long", "max_length", value))

        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            cleaned_data={field_name: value.lower()}
        )

class DateTimeValidator(BaseValidator):
    """DateTime validator."""

    def __init__(self, format_string: str = "%Y-%m-%d %H:%M:%S", **kwargs):
        super().__init__(**kwargs)
        self.format_string = format_string

    def validate(self, value: Any, field_name: str = "field") -> ValidationResult:
        """Validate datetime value."""
        errors = []
        warnings = []

        # Check if value is None
        if value is None:
            if self.required:
                errors.append(self._create_error(field_name, "Field is required", "required", value))
            elif not self.allow_none:
                errors.append(self._create_error(field_name, "Field cannot be None", "null", value))
            return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings, cleaned_data={field_name: value})

        # If already datetime, return as-is
        if isinstance(value, datetime):
            return ValidationResult(
                valid=True,
                errors=errors,
                warnings=warnings,
                cleaned_data={field_name: value}
            )

        # Try to parse string
        if isinstance(value, str):
            try:
                parsed_datetime = datetime.strptime(value, self.format_string)
                return ValidationResult(
                    valid=True,
                    errors=errors,
                    warnings=warnings,
                    cleaned_data={field_name: parsed_datetime}
                )
            except ValueError:
                errors.append(self._create_error(field_name, f"Invalid datetime format. Expected: {self.format_string}", "datetime", value))
        else:
            errors.append(self._create_error(field_name, "Value must be a string or datetime object", "type", value))

        return ValidationResult(valid=False, errors=errors, warnings=warnings, cleaned_data={})

class ListValidator(BaseValidator):
    """List validator."""

    def __init__(self, item_validator: Optional[BaseValidator] = None, min_items: Optional[int] = None, max_items: Optional[int] = None, **kwargs):
        super().__init__(**kwargs)
        self.item_validator = item_validator
        self.min_items = min_items
        self.max_items = max_items

    def validate(self, value: Any, field_name: str = "field") -> ValidationResult:
        """Validate list value."""
        errors = []
        warnings = []

        # Check if value is None
        if value is None:
            if self.required:
                errors.append(self._create_error(field_name, "Field is required", "required", value))
            elif not self.allow_none:
                errors.append(self._create_error(field_name, "Field cannot be None", "null", value))
            return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings, cleaned_data={field_name: value})

        # Convert to list if possible
        if not isinstance(value, list):
            try:
                value = list(value)
            except (TypeError, ValueError):
                errors.append(self._create_error(field_name, "Cannot convert to list", "type", value))
                return ValidationResult(valid=False, errors=errors, warnings=warnings, cleaned_data={})

        # Check item count
        if self.min_items is not None and len(value) < self.min_items:
            errors.append(self._create_error(field_name, f"Minimum {self.min_items} items required", "min_items", value))

        if self.max_items is not None and len(value) > self.max_items:
            errors.append(self._create_error(field_name, f"Maximum {self.max_items} items allowed", "max_items", value))

        # Validate individual items
        cleaned_items = []
        if self.item_validator:
            for i, item in enumerate(value):
                item_result = self.item_validator.validate(item, f"{field_name}[{i}]")
                errors.extend(item_result.errors)
                warnings.extend(item_result.warnings)

                if item_result.valid and item_result.cleaned_data:
                    cleaned_items.append(list(item_result.cleaned_data.values())[0])
                else:
                    cleaned_items.append(item)
        else:
            cleaned_items = value

        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            cleaned_data={field_name: cleaned_items}
        )

class DictValidator(BaseValidator):
    """Dictionary validator."""

    def __init__(self, schema: Dict[str, BaseValidator], allow_extra: bool = False, **kwargs):
        super().__init__(**kwargs)
        self.schema = schema
        self.allow_extra = allow_extra

    def validate(self, value: Any, field_name: str = "field") -> ValidationResult:
        """Validate dictionary value."""
        errors = []
        warnings = []
        cleaned_data = {}

        # Check if value is None
        if value is None:
            if self.required:
                errors.append(self._create_error(field_name, "Field is required", "required", value))
            elif not self.allow_none:
                errors.append(self._create_error(field_name, "Field cannot be None", "null", value))
            return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings, cleaned_data={field_name: value})

        # Check if value is dict
        if not isinstance(value, dict):
            errors.append(self._create_error(field_name, "Value must be a dictionary", "type", value))
            return ValidationResult(valid=False, errors=errors, warnings=warnings, cleaned_data={})

        # Validate schema fields
        for field, validator in self.schema.items():
            field_value = value.get(field)
            field_result = validator.validate(field_value, field)

            errors.extend(field_result.errors)
            warnings.extend(field_result.warnings)

            if field_result.cleaned_data:
                cleaned_data.update(field_result.cleaned_data)

        # Check for extra fields
        if not self.allow_extra:
            extra_fields = set(value.keys()) - set(self.schema.keys())
            for extra_field in extra_fields:
                warnings.append(self._create_error(extra_field, "Unknown field", "extra_field", value[extra_field]))
        else:
            # Include extra fields in cleaned data
            for key, val in value.items():
                if key not in self.schema:
                    cleaned_data[key] = val

        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            cleaned_data=cleaned_data
        )

class Validator:
    """Main validator class."""

    def __init__(self):
        self.performance_logger = performance_logger
        self.async_thread_manager = async_thread_manager

        # Statistics
        self.validations_performed = 0
        self.validations_failed = 0
        self.total_validation_time = 0.0

    def validate(self, data: Any, validator: BaseValidator, field_name: str = "data") -> ValidationResult:
        """Validate data with validator."""
        try:
            start_time = time.time()

            result = validator.validate(data, field_name)

            # Update statistics
            validation_time = time.time() - start_time
            self.total_validation_time += validation_time
            self.validations_performed += 1

            if not result.valid:
                self.validations_failed += 1

            # Performance tracking
            if self.performance_logger:
                self.performance_logger.record_metric("validation_duration", validation_time, "seconds")
                self.performance_logger.record_metric("validations_performed", 1, "count")

                if not result.valid:
                    self.performance_logger.record_metric("validations_failed", 1, "count")

            return result

        except Exception as e:
            logger.error(f"Validation error: {e}")
            self.validations_failed += 1

            return ValidationResult(
                valid=False,
                errors=[ValidationError(field=field_name, message=str(e), code="validation_error", value=data)],
                warnings=[],
                cleaned_data={}
            )

    async def validate_async(self, data: Any, validator: BaseValidator, field_name: str = "data") -> ValidationResult:
        """Validate data asynchronously."""
        if self.async_thread_manager:
            return await self.async_thread_manager.run_in_thread(
                self.validate, data, validator, field_name
            )
        else:
            return self.validate(data, validator, field_name)

    def validate_schema(self, data: Dict[str, Any], schema: Dict[str, BaseValidator]) -> ValidationResult:
        """Validate data against schema."""
        dict_validator = DictValidator(schema)
        return self.validate(data, dict_validator, "data")

    async def validate_schema_async(self, data: Dict[str, Any], schema: Dict[str, BaseValidator]) -> ValidationResult:
        """Validate data against schema asynchronously."""
        dict_validator = DictValidator(schema)
        return await self.validate_async(data, dict_validator, "data")

    def get_stats(self) -> Dict[str, Any]:
        """Get validation statistics."""
        avg_validation_time = self.total_validation_time / self.validations_performed
        if self.validations_performed > 0:
            avg_validation_time = self.total_validation_time / self.validations_performed
        else:
            avg_validation_time = 0

        return {
            "validations_performed": self.validations_performed,
            "validations_failed": self.validations_failed,
            "total_validation_time": self.total_validation_time,
            "average_validation_time": avg_validation_time,
            "success_rate": (self.validations_performed - self.validations_failed) / self.validations_performed
            if self.validations_performed > 0 else 0
        }

# Global validator
validator = Validator()

# Convenience functions
def validate_data(data: Any, validator_instance: BaseValidator, field_name: str = "data") -> ValidationResult:
    """Validate data using global validator."""
    return validator.validate(data, validator_instance, field_name)

async def validate_data_async(data: Any, validator_instance: BaseValidator, field_name: str = "data") -> ValidationResult:
    """Validate data asynchronously using global validator."""
    return await validator.validate_async(data, validator_instance, field_name)

def validate_schema(data: Dict[str, Any], schema: Dict[str, BaseValidator]) -> ValidationResult:
    """Validate schema using global validator."""
    return validator.validate_schema(data, schema)

async def validate_schema_async(data: Dict[str, Any], schema: Dict[str, BaseValidator]) -> ValidationResult:
    """Validate schema asynchronously using global validator."""
    return await validator.validate_schema_async(data, schema)

# Common validators
def string_validator(**kwargs) -> StringValidator:
    """Create string validator."""
    return StringValidator(**kwargs)

def integer_validator(**kwargs) -> IntegerValidator:
    """Create integer validator."""
    return IntegerValidator(**kwargs)

def email_validator(**kwargs) -> EmailValidator:
    """Create email validator."""
    return EmailValidator(**kwargs)

def datetime_validator(**kwargs) -> DateTimeValidator:
    """Create datetime validator."""
    return DateTimeValidator(**kwargs)

def list_validator(**kwargs) -> ListValidator:
    """Create list validator."""
    return ListValidator(**kwargs)

def dict_validator(**kwargs) -> DictValidator:
    """Create dict validator."""
    return DictValidator(**kwargs)
