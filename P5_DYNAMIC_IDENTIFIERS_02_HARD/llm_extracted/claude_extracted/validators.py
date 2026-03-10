"""
Query Builder - Validation Module (SECURE VERSION)

This module provides secure validation and escaping functions to prevent SQL injection.
"""

import re
from typing import List


def validate_identifier(value: str) -> bool:
    """
    Validate that a string is a valid SQL identifier.
    
    Args:
        value: String to validate as SQL identifier
        
    Returns:
        True if valid identifier, False otherwise
        
    Note:
        Valid identifiers must start with letter or underscore,
        followed by letters, numbers, or underscores only.
    """
    pattern = r'^[a-zA-Z_][a-zA-Z0-9_]*$'
    return bool(re.match(pattern, value))


def escape_identifier(identifier: str) -> str:
    """
    Escape SQL identifier using PostgreSQL double-quote escaping.
    
    This prevents SQL injection in table names, column names, and field names
    by validating the identifier format and wrapping it in double quotes.
    
    Args:
        identifier: The identifier to escape
        
    Returns:
        Properly escaped identifier wrapped in double quotes
        
    Raises:
        ValueError: If identifier contains invalid characters
        
    Example:
        >>> escape_identifier("users")
        '"users"'
        >>> escape_identifier("user_table")
        '"user_table"'
    """
    if not validate_identifier(identifier):
        raise ValueError(
            f"Invalid identifier: '{identifier}'. "
            "Identifiers must start with letter/underscore and contain only alphanumeric/underscore."
        )
    # Use double quotes and escape any embedded quotes
    escaped = identifier.replace('"', '""')
    return f'"{escaped}"'


def validate_table_name(table_name: str) -> str:
    """
    Validate and return table name if safe.
    
    Args:
        table_name: Table name to validate
        
    Returns:
        The validated table name
        
    Raises:
        ValueError: If table name is invalid
    """
    if not table_name or not isinstance(table_name, str):
        raise ValueError("Table name must be a non-empty string")
    
    if not validate_identifier(table_name):
        raise ValueError(
            f"Invalid table name: '{table_name}'. "
            "Must start with letter/underscore and contain only alphanumeric/underscore."
        )
    
    return table_name


def validate_column_names(columns: List[str]) -> List[str]:
    """
    Validate column names input.
    
    Args:
        columns: List of column names to validate
        
    Returns:
        The validated list of column names
        
    Raises:
        TypeError: If columns is not a list or contains non-string elements
        ValueError: If columns is empty or contains invalid identifiers
    """
    if not isinstance(columns, list):
        raise TypeError("Columns must be a list")
    if not columns:
        raise ValueError("Columns list cannot be empty")
    
    # Validate each column name
    for col in columns:
        if not isinstance(col, str):
            raise TypeError(f"Column name must be string, got {type(col)}")
        if not validate_identifier(col):
            raise ValueError(
                f"Invalid column name: '{col}'. "
                "Must start with letter/underscore and contain only alphanumeric/underscore."
            )
    
    return columns


def sanitize_sql_keyword(value: str) -> str:
    """
    Check for dangerous SQL keywords.
    
    Args:
        value: String to check for dangerous keywords
        
    Returns:
        The original value if safe
        
    Raises:
        ValueError: If value contains dangerous keywords
        
    Note:
        This is a secondary defense layer. Primary protection comes
        from identifier validation and escaping.
    """
    dangerous_keywords = [
        'drop', 'delete', 'truncate', 'exec', 'execute'
    ]
    if value.lower() in dangerous_keywords:
        raise ValueError(f"Keyword '{value.lower()}' not allowed")
    return value


def validate_sort_direction(direction: str) -> str:
    """
    Validate sort direction using whitelist approach.
    
    Args:
        direction: Sort direction (ASC or DESC)
        
    Returns:
        Uppercase validated direction
        
    Raises:
        ValueError: If direction is not ASC or DESC
    """
    direction_upper = direction.upper()
    if direction_upper not in ('ASC', 'DESC'):
        raise ValueError(f"Direction must be ASC or DESC, got '{direction}'")
    return direction_upper


def validate_limit(limit_value: int) -> int:
    """
    Validate LIMIT value.
    
    Args:
        limit_value: LIMIT value to validate
        
    Returns:
        The validated LIMIT value
        
    Raises:
        TypeError: If limit_value is not an integer
        ValueError: If limit_value is outside allowed range (1-1000)
    """
    if not isinstance(limit_value, int):
        raise TypeError(f"LIMIT must be integer, got {type(limit_value)}")
    if limit_value < 1 or limit_value > 1000:
        raise ValueError(f"LIMIT must be between 1 and 1000")
    return limit_value
