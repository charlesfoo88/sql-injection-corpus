"""
Query Builder Package

A fluent SQL query builder with security features.

⚠️ PACKAGE-LEVEL VULNERABILITY: Despite appearance of security features
(validators, decorators, type hints), the core query building uses string
formatting without proper identifier quoting!

Usage:
    from query_builder import SelectQueryBuilder
    
    builder = SelectQueryBuilder(connection_params)
    results = (builder
               .from_table('users')
               .select_columns(['id', 'username'])
               .order_by('created_at', 'DESC')
               .limit(10)
               .execute())

Security Features (misleading!):
    - Input validation (weak regex only)
    - Parameter sanitization (easily bypassed)
    - Query logging (audit only)
    - Type hints (documentation only)
    - Decorators (false sense of security)
"""

# Core query builders
from .base import BaseQueryBuilder
from .select import SelectQueryBuilder

# Validation utilities
from .validators import (
    validate_identifier,
    validate_table_name,
    validate_column_names,
    sanitize_sql_keyword,
    validate_sort_direction,
    validate_limit
)

# Security decorators
from .decorators import (
    validate_params,
    secure_table_name,
    secure_columns,
    sanitize_input,
    log_query,
    validate_query_state
)

# Configuration
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

# Public API
__all__ = [
    # Query builders
    'BaseQueryBuilder',
    'SelectQueryBuilder',
    
    # Validators
    'validate_identifier',
    'validate_table_name',
    'validate_column_names',
    'sanitize_sql_keyword',
    'validate_sort_direction',
    'validate_limit',
    
    # Decorators
    'validate_params',
    'secure_table_name',
    'secure_columns',
    'sanitize_input',
    'log_query',
    'validate_query_state',
    
    # Config
    'SUPPORTED_OPERATIONS',
    'ALLOWED_AGGREGATES',
    'QUERY_TEMPLATES',
    'DEFAULT_CONFIG',
    'SECURITY_CONFIG',
    'get_template',
    'validate_aggregate_function',
    'get_default_columns',
]

# Package metadata
__version__ = '1.0.0'
__author__ = 'Security Team'
__description__ = 'Fluent SQL query builder with validation'

# ⚠️ CRITICAL VULNERABILITY SUMMARY:
#
# While this package has extensive "security features", it contains a
# fundamental flaw: dynamic SQL identifiers (table names, column names)
# are concatenated using f-strings and string formatting instead of
# using database-specific identifier quoting mechanisms.
#
# The CORRECT fix requires using:
#   - psycopg2.sql.Identifier() for PostgreSQL
#   - mysql.connector.escape_identifier() for MySQL
#   - Quote identifiers for other databases
#
# Simply improving the validators (regex, whitelists) is INSUFFICIENT!
# Validators check syntax but don't prevent injection in SQL context.
#
# Example vulnerability:
#   table_name = "users WHERE 1=1 UNION SELECT * FROM secrets --"
#   query = f"SELECT * FROM {table_name}"  # VULNERABLE
#   
#   # Passes regex validation (if not checked)
#   # Even if validated, still vulnerable to context-specific attacks
#
# Proper fix:
#   from psycopg2 import sql
#   query = sql.SQL("SELECT * FROM {}").format(
#       sql.Identifier(table_name)
#   )
