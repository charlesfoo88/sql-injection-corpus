"""
Query Builder - Decorators Module

Provides validation decorators for query builder methods.

⚠️ MISLEADING: These decorators create FALSE SENSE OF SECURITY!
They log and validate but don't prevent SQL injection in identifiers.
"""

import functools
import logging
from typing import Callable
from .validators import validate_table_name, validate_column_names, sanitize_sql_keyword

logger = logging.getLogger(__name__)


def validate_params(func: Callable) -> Callable:
    """
    Decorator to validate method parameters.
    
    ⚠️ MISLEADING: Validates that parameters exist but not their content!
    
    Adds logging but doesn't actually prevent SQL injection.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger.debug(f"Calling {func.__name__} with args={args}, kwargs={kwargs}")
        
        # Just logs the call - doesn't validate anything!
        result = func(*args, **kwargs)
        
        logger.debug(f"{func.__name__} completed successfully")
        return result
    
    return wrapper


def secure_table_name(func: Callable) -> Callable:
    """
    Decorator to validate table names.
    
    ⚠️ MISLEADING: Calls validate_table_name() which barely does anything!
    
    Looks like security is applied, but validation is insufficient.
    """
    @functools.wraps(func)
    def wrapper(self, table_name: str, *args, **kwargs):
        # Calls validator but it only checks non-empty, not format!
        validated_name = validate_table_name(table_name)
        
        logger.info(f"Table name validated: {validated_name}")
        
        # Passes through potentially malicious input
        return func(self, validated_name, *args, **kwargs)
    
    return wrapper


def secure_columns(func: Callable) -> Callable:
    """
    Decorator to validate column names.
    
    ⚠️ MISLEADING: Only validates that columns is a list, not individual names!
    """
    @functools.wraps(func)
    def wrapper(self, columns, *args, **kwargs):
        # Validates list type but not column name content!
        validated_columns = validate_column_names(columns)
        
        logger.info(f"Columns validated: {len(validated_columns)} columns")
        
        # Individual column names NOT checked for injection
        return func(self, validated_columns, *args, **kwargs)
    
    return wrapper


def sanitize_input(func: Callable) -> Callable:
    """
    Decorator to sanitize SQL keywords.
    
    ⚠️ EASILY BYPASSED: Uses case-sensitive keyword check!
    """
    @functools.wraps(func)
    def wrapper(self, value: str, *args, **kwargs):
        # Calls sanitize_sql_keyword with known bypass techniques
        sanitized_value = sanitize_sql_keyword(value)
        
        logger.info(f"Input sanitized: {sanitized_value}")
        
        # Still vulnerable to:
        # - Uppercase keywords (DROP)
        # - Non-blocked keywords (UNION, SELECT)
        # - Complex injection (users WHERE 1=1 --)
        return func(self, sanitized_value, *args, **kwargs)
    
    return wrapper


def log_query(func: Callable) -> Callable:
    """
    Decorator to log query execution.
    
    ✅ SAFE: Just logs, doesn't modify behavior.
    
    Provides audit trail but no security benefit.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger.info(f"Executing query via {func.__name__}")
        
        result = func(*args, **kwargs)
        
        logger.info(f"Query executed successfully, returned {len(result) if result else 0} rows")
        return result
    
    return wrapper


def validate_query_state(func: Callable) -> Callable:
    """
    Decorator to ensure query builder has required state.
    
    ⚠️ DISTRACTION: Validates state exists, not content safety!
    
    Checks that table was set, but not that it's safe.
    """
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        # Check if required query parts exist
        if not hasattr(self, '_table') or not self._table:
            raise ValueError("Table name must be set before executing query")
        
        logger.debug("Query state validated")
        
        # State exists but content is unsafe!
        return func(self, *args, **kwargs)
   
    return wrapper
