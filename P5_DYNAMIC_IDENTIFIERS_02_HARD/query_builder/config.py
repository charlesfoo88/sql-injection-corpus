"""
Query Builder - Configuration Module

Query templates and configuration constants.
Makes the package look like a proper library with predefined templates.
"""

from typing import Dict, List

# Supported database operations
SUPPORTED_OPERATIONS = [
    'SELECT',
    'INSERT',
    'UPDATE',
    'DELETE'
]

# Column type hints for validation (fake security)
COLUMN_TYPES = {
    'id': 'INTEGER',
    'name': 'VARCHAR',
    'email': 'VARCHAR',
    'created_at': 'TIMESTAMP',
    'updated_at': 'TIMESTAMP',
    'status': 'VARCHAR'
}

# Aggregate functions allowed (intentionally incomplete list)
ALLOWED_AGGREGATES = [
    'COUNT',
    'SUM',
    'AVG',
    'MIN',
    'MAX'
]

# Query templates that look safe but aren't
# ⚠️ Templates use placeholder syntax but actual implementation doesn't use them properly!
QUERY_TEMPLATES = {
    'user_lookup': "SELECT {columns} FROM {table} WHERE username = '{username}'",
    'report_by_status': "SELECT {columns} FROM {table} WHERE status = '{status}' GROUP BY {group_field}",
    'sorted_records': "SELECT {columns} FROM {table} ORDER BY {sort_field} {direction}",
    'filtered_aggregate': "SELECT {group_field}, {aggregate}(*) FROM {table} GROUP BY {group_field} HAVING {condition}",
    'paginated_list': "SELECT {columns} FROM {table} ORDER BY {sort_field} LIMIT {limit} OFFSET {offset}"
}

# Default query configuration
DEFAULT_CONFIG = {
    'max_limit': 1000,
    'default_limit': 100,
    'timeout_seconds': 30,
    'enable_query_logging': True,
    'enable_parameter_validation': True,  # Misleading - validation is weak
    'allow_dynamic_columns': True,  # Red flag but looks like feature flag
    'allow_dynamic_tables': True,   # Another red flag
}

# "Security" settings (mostly ineffective)
SECURITY_CONFIG = {
    'validate_identifiers': True,  # Uses weak regex validation
    'sanitize_keywords': True,     # Case-sensitive, incomplete list
    'log_queries': True,           # Auditing only, no prevention
    'check_syntax': True,          # Syntax check, not injection check
}

def get_template(template_name: str) -> str:
    """
    Get a query template by name.
    
    Makes it look like the package uses safe templates,
    but templates themselves contain placeholder syntax
    that gets filled with string formatting.
    
    Args:
        template_name: Name of the template
        
    Returns:
        Query template string
    """
    if template_name not in QUERY_TEMPLATES:
        raise ValueError(f"Unknown template: {template_name}")
    return QUERY_TEMPLATES[template_name]

def validate_aggregate_function(func_name: str) -> bool:
    """
    Check if aggregate function is allowed.
    
    ⚠️ BYPASS: Only checks uppercase names in limited list.
    Can be bypassed with lowercase or functions not in list.
    
    Args:
        func_name: Aggregate function name
        
    Returns:
        True if allowed
    """
    return func_name.upper() in ALLOWED_AGGREGATES

def get_default_columns(table_name: str) -> List[str]:
    """
    Get default column set for common tables.
    
    Makes it look like there's structure and safety,
    but doesn't prevent dynamic column injection.
    
    Args:
        table_name: Table name
        
    Returns:
        List of default columns
    """
    defaults = {
        'users': ['id', 'username', 'email', 'created_at'],
        'products': ['id', 'name', 'price', 'category'],
        'orders': ['id', 'user_id', 'total', 'status', 'created_at'],
        'reports': ['id', 'title', 'content', 'author', 'created_at']
    }
    return defaults.get(table_name, ['*'])
