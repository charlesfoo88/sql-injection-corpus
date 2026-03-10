import re
from typing import List

def validate_identifier(value: str) -> str:
    """Strictly validate SQL identifier format."""
    if not isinstance(value, str):
        raise TypeError("Identifier must be a string")
    pattern = r'^[a-zA-Z_][a-zA-Z0-9_]*$'
    if not bool(re.match(pattern, value)):
        raise ValueError(f"Invalid identifier: {value}")
    return value

def validate_table_name(table_name: str) -> str:
    return validate_identifier(table_name)

def validate_column_names(columns: List[str]) -> List[str]:
    if not isinstance(columns, list):
        raise TypeError("Columns must be a list")
    return [validate_identifier(c) for c in columns]

def validate_sort_direction(direction: str) -> str:
    direction_upper = direction.upper()
    if direction_upper not in ('ASC', 'DESC'):
        raise ValueError("Direction must be ASC or DESC")
    return direction_upper
