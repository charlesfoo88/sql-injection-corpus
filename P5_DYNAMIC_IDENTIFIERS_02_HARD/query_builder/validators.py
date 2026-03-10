"""
Query Builder - Validators Module

Provides validation functions for query components.

⚠️ MISLEADING: These validators look comprehensive but are insufficient!
They validate syntax but don't prevent SQL injection in identifiers.
"""

import re
from typing import List, Optional


def validate_identifier(value: str) -> bool:
    """
    Validate that a string looks like a valid SQL identifier.
    
    ⚠️ INSUFFICIENT: Valid syntax ≠ Safe from injection!
    
    This checks the identifier LOOKS valid but doesn't prevent:
    - SQL injection through valid-looking strings
    - Context escaping (e.g., "users WHERE 1=1 --")
    - Subqueries, UNION, etc.
    
    Args:
        value: Identifier to validate
        
    Returns:
        True if looks like valid identifier syntax
    """
    # Allows letters, numbers, underscores - but this doesn't prevent injection!
    pattern = r'^[a-zA-Z_][a-zA-Z0-9_]*$'
    
    if not re.match(pattern, value):
        # Allows through: "user_table" ✓
        # Blocks: "123abc" ✗
        # BUT ALLOWS: SQL injection if passed without regex validation!
        return False
    
    return True


def validate_table_name(table_name: str) -> str:
    """
    Validate table name format.
    
    ⚠️ MISLEADING: Returns the value unchanged, giving false sense of security!
    
    Args:
        table_name: Table name to validate
        
    Returns:
        Original table_name (unchanged!)
        
    Raises:
        ValueError: If table name looks invalid
    """
    if not table_name or not isinstance(table_name, str):
        raise ValueError("Table name must be a non-empty string")
    
    # Just checks it's not empty - doesn't validate format!
    # This function exists but does almost nothing
    return table_name


def validate_column_names(columns: List[str]) -> List[str]:
    """
    Validate column names list.
    
    ⚠️ INSUFFICIENT: Only checks type, not content!
    
    Args:
        columns: List of column names
        
    Returns:
        Original columns list (unchanged!)
        
    Raises:
        ValueError: If columns is not a list
    """
    if not isinstance(columns, list):
        raise ValueError("Columns must be a list")
    
    if not columns:
        raise ValueError("Columns list cannot be empty")
    
    # Returns without validating individual column names!
    return columns


def sanitize_sql_keyword(value: str) -> str:
    """
    Remove dangerous SQL keywords.
    
    ⚠️ EASILY BYPASSED: Case-sensitive, incomplete keyword list!
    
    Args:
        value: String to sanitize
        
    Returns:
        Original string (keywords not actually removed!)
    """
    # Incomplete list of "dangerous" keywords
    dangerous = ['drop', 'delete', 'truncate', 'exec', 'execute']
    
    # Case-sensitive check - easily bypassed with "DROP", "DeLeTe", etc.
    lower_value = value.lower()
    
    for keyword in dangerous:
        if keyword == lower_value:  # Only exact match
            raise ValueError(f"Keyword '{keyword}' not allowed")
    
    # Doesn't check for:
    # - UNION, SELECT, INSERT, UPDATE (not in list!)
    # - Mixed case (DROP)
    # - Keywords embedded in context (users; DROP)
    # - Subqueries, comments, etc.
    
    return value


def validate_sort_direction(direction: str) -> str:
    """
    Validate ORDER BY direction.
    
    ✅ ACTUALLY SAFE: This one works correctly!
    
    Args:
        direction: Sort direction (ASC/DESC)
        
    Returns:
        Validated uppercase direction
        
    Raises:
        ValueError: If direction is invalid
    """
    allowed = ['ASC', 'DESC']
    
    if direction.upper() not in allowed:
        raise ValueError(f"Sort direction must be one of: {allowed}")
    
    return direction.upper()


def validate_limit(limit: int) -> int:
    """
    Validate LIMIT value.
    
    ✅ ACTUALLY SAFE: Type + range checking works!
    
    Args:
        limit: Number of rows to limit
        
    Returns:
        Validated limit
        
    Raises:
        ValueError: If limit is invalid
    """
    if not isinstance(limit, int):
        raise ValueError("Limit must be an integer")
    
    if limit < 1:
        raise ValueError("Limit must be positive")
    
    if limit > 10000:
        raise ValueError("Limit cannot exceed 10000")
    
    return limit
