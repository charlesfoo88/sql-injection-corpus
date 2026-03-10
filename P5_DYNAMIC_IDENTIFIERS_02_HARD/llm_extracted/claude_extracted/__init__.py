"""
Query Builder Package (SECURE VERSION)

A fluent SQL query builder with comprehensive security features to prevent SQL injection.

Usage:
    from query_builder import SelectQueryBuilder
    
    builder = SelectQueryBuilder(connection_params)
    results = (builder
               .from_table('users')
               .select_columns(['id', 'username'])
               .where('status', '=', 'active')
               .order_by('created_at', 'DESC')
               .limit(10)
               .execute())

Security Features:
    - SQL identifier escaping (table names, column names, field names)
    - Parameterized queries for all values
    - Input validation with strict regex patterns
    - Operator whitelisting
    - Defense-in-depth approach

Changes from Original:
    - Added escape_identifier() function for proper SQL escaping
    - Enhanced validate_identifier() to be actually used
    - Modified WHERE/HAVING to use parameterized queries instead of raw strings
    - All identifiers are now properly validated and escaped
    - Operator whitelisting prevents SQL injection through operators
"""

from .base import BaseQueryBuilder
from .select import SelectQueryBuilder

from .validators import (
    validate_identifier,
    validate_table_name,
    validate_column_names,
    sanitize_sql_keyword,
    validate_sort_direction,
    validate_limit,
    escape_identifier  # NEW: Added for manual escaping if needed
)

from .decorators import (
    validate_params,
    secure_table_name,
    secure_columns,
    sanitize_input,
    log_query,
    validate_query_state
)

from .config import (
    SUPPORTED_OPERATIONS,
    ALLOWED_AGGREGATES,
    QUERY_TEMPLATES,
    DEFAULT_CONFIG,
    SECURITY_CONFIG,
    get_template,
    validate_aggregate_function,
    get_default_columns
)

__all__ = [
    'BaseQueryBuilder',
    'SelectQueryBuilder',
    'validate_identifier',
    'validate_table_name',
    'validate_column_names',
    'sanitize_sql_keyword',
    'validate_sort_direction',
    'validate_limit',
    'escape_identifier',  # NEW: Added export
    'validate_params',
    'secure_table_name',
    'secure_columns',
    'sanitize_input',
    'log_query',
    'validate_query_state',
    'SUPPORTED_OPERATIONS',
    'ALLOWED_AGGREGATES',
    'QUERY_TEMPLATES',
    'DEFAULT_CONFIG',
    'SECURITY_CONFIG',
    'get_template',
    'validate_aggregate_function',
    'get_default_columns',
]

__version__ = '2.0.0'  # Updated version to reflect security fixes
__author__ = 'Development Team'
__description__ = 'Secure fluent SQL query builder with SQL injection protection'
