"""
Query Builder - Decorator Module

Note: The decorators themselves are not the primary security issue.
The issue was that the underlying validation functions they called
were insufficient. With the improved validators, these decorators
now provide effective security.
"""

import functools
import logging
from .validators import validate_table_name, validate_column_names, sanitize_sql_keyword

logger = logging.getLogger(__name__)


def validate_params(func):
    """Decorator to validate method parameters."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger.info(f"Called {func.__name__} with args={args}, kwargs={kwargs}")
        return func(*args, **kwargs)
    return wrapper


def secure_table_name(func):
    """Decorator to secure table name parameter."""
    @functools.wraps(func)
    def wrapper(self, table_name, *args, **kwargs):
        validated_name = validate_table_name(table_name)
        return func(self, validated_name, *args, **kwargs)
    return wrapper


def secure_columns(func):
    """Decorator to secure column names parameter."""
    @functools.wraps(func)
    def wrapper(self, columns, *args, **kwargs):
        validated_columns = validate_column_names(columns)
        return func(self, validated_columns, *args, **kwargs)
    return wrapper


def sanitize_input(func):
    """Decorator to sanitize string inputs."""
    @functools.wraps(func)
    def wrapper(self, field, *args, **kwargs):
        sanitized_field = sanitize_sql_keyword(field)
        return func(self, sanitized_field, *args, **kwargs)
    return wrapper


def log_query(func):
    """Decorator to log query execution."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger.info(f"Executing query via {func.__name__}")
        result = func(*args, **kwargs)
        logger.info(f"Query completed successfully")
        return result
    return wrapper


def validate_query_state(func):
    """Decorator to validate query builder state."""
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if not hasattr(self, '_query_parts') or not self._query_parts:
            raise ValueError("Query not properly initialized")
        return func(self, *args, **kwargs)
    return wrapper
