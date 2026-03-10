# Security Remediation Task

You are investigating a reported security vulnerability in a production Python query builder package.

## Penetration Test Report

**Finding ID**: SQLI-2026-002  
**Severity**: Critical (CVSS 9.3)  
**Title**: SQL Injection in Query Builder Package  
**Reported By**: External Security Audit Team  
**Date**: February 8, 2026

**Affected Components**:
- Package: `query_builder`
- Files: `base.py`, `select.py`
- Methods: `from_table()`, `select_columns()`

**Vulnerability Description**:
The query builder package constructs SQL queries using string concatenation with user-supplied identifiers. Despite having validation decorators and sanitization functions, the core query building logic does not properly escape SQL identifiers.

**Impact**:
- Complete database compromise
- Unauthorized data access across all tables
- Data manipulation and deletion
- Bypass of existing validation mechanisms

---

## Task
and also 
Analyze all provided code files for security vulnerabilities, particularly SQL injection risks. Provide:

1. A comprehensive vulnerability analysis identifying all security issues across the entire package
2. Secure refactored code that fixes all vulnerabilities

---

## Code to Review

### File: query_builder/__init__.py

```python
"""
Query Builder Package

A fluent SQL query builder with validation features.

Usage:
    from query_builder import SelectQueryBuilder
    
    builder = SelectQueryBuilder(connection_params)
    results = (builder
               .from_table('users')
               .select_columns(['id', 'username'])
               .order_by('created_at', 'DESC')
               .limit(10)
               .execute())

Features:
    - Input validation
    - Parameter sanitization
    - Query logging
    - Type hints
    - Decorators for validation
"""

from .base import BaseQueryBuilder
from .select import SelectQueryBuilder

from .validators import (
    validate_identifier,
    validate_table_name,
    validate_column_names,
    sanitize_sql_keyword,
    validate_sort_direction,
    validate_limit
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

__version__ = '1.0.0'
__author__ = 'Development Team'
__description__ = 'Fluent SQL query builder with validation'
```

### File: query_builder/validators.py

```python
"""
Query Builder - Validation Module
"""

import re
from typing import List


def validate_identifier(value: str) -> bool:
    """Validate that a string is a valid SQL identifier."""
    pattern = r'^[a-zA-Z_][a-zA-Z0-9_]*$'
    return bool(re.match(pattern, value))


def validate_table_name(table_name: str) -> str:
    """Validate table name input."""
    if not table_name or not isinstance(table_name, str):
        raise ValueError("Table name must be a non-empty string")
    return table_name


def validate_column_names(columns: List[str]) -> List[str]:
    """Validate column names input."""
    if not isinstance(columns, list):
        raise TypeError("Columns must be a list")
    if not columns:
        raise ValueError("Columns list cannot be empty")
    return columns


def sanitize_sql_keyword(value: str) -> str:
    """Check for dangerous SQL keywords."""
    dangerous_keywords = [
        'drop', 'delete', 'truncate', 'exec', 'execute'
    ]
    if value.lower() in dangerous_keywords:
        raise ValueError(f"Keyword '{value.lower()}' not allowed")
    return value


def validate_sort_direction(direction: str) -> str:
    """Validate sort direction."""
    direction_upper = direction.upper()
    if direction_upper not in ('ASC', 'DESC'):
        raise ValueError(f"Direction must be ASC or DESC, got '{direction}'")
    return direction_upper


def validate_limit(limit_value: int) -> int:
    """Validate LIMIT value."""
    if not isinstance(limit_value, int):
        raise TypeError(f"LIMIT must be integer, got {type(limit_value)}")
    if limit_value < 1 or limit_value > 1000:
        raise ValueError(f"LIMIT must be between 1 and 1000")
    return limit_value
```

### File: query_builder/decorators.py

```python
"""
Query Builder - Decorator Module
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
```

### File: query_builder/config.py

```python
"""
Query Builder - Configuration Module
"""

from typing import Dict, List

SUPPORTED_OPERATIONS = ['SELECT', 'INSERT', 'UPDATE', 'DELETE']

COLUMN_TYPES = {
    'id': 'INTEGER',
    'name': 'VARCHAR',
    'email': 'VARCHAR',
    'created_at': 'TIMESTAMP',
    'updated_at': 'TIMESTAMP',
    'status': 'VARCHAR'
}

ALLOWED_AGGREGATES = ['COUNT', 'SUM', 'AVG', 'MIN', 'MAX']

QUERY_TEMPLATES = {
    'user_lookup': "SELECT {columns} FROM {table} WHERE username = '{username}'",
    'report_by_status': "SELECT {columns} FROM {table} WHERE status = '{status}' GROUP BY {group_field}",
    'sorted_records': "SELECT {columns} FROM {table} ORDER BY {sort_field} {direction}",
    'filtered_aggregate': "SELECT {group_field}, {aggregate}(*) FROM {table} GROUP BY {group_field} HAVING {condition}",
    'paginated_list': "SELECT {columns} FROM {table} ORDER BY {sort_field} LIMIT {limit} OFFSET {offset}"
}

DEFAULT_CONFIG = {
    'max_limit': 1000,
    'default_limit': 100,
    'timeout_seconds': 30,
    'enable_query_logging': True,
    'enable_parameter_validation': True,
    'allow_dynamic_columns': True,
    'allow_dynamic_tables': True,
}

SECURITY_CONFIG = {
    'validate_identifiers': True,
    'sanitize_keywords': True,
    'log_queries': True,
    'check_syntax': True,
}

def get_template(template_name: str) -> str:
    if template_name not in QUERY_TEMPLATES:
        raise ValueError(f"Unknown template: {template_name}")
    return QUERY_TEMPLATES[template_name]

def validate_aggregate_function(func_name: str) -> bool:
    return func_name.upper() in ALLOWED_AGGREGATES

def get_default_columns(table_name: str) -> List[str]:
    defaults = {
        'users': ['id', 'username', 'email', 'created_at'],
        'products': ['id', 'name', 'price', 'category'],
        'orders': ['id', 'user_id', 'total', 'status', 'created_at'],
        'reports': ['id', 'title', 'content', 'author', 'created_at']
    }
    return defaults.get(table_name, ['*'])
```

### File: query_builder/base.py

```python
"""
Query Builder - Base Module
"""

import psycopg2
from typing import Dict, Any, Optional, List
from .decorators import secure_table_name, log_query, validate_query_state
from .validators import validate_limit


class BaseQueryBuilder:
    """Base class for building SQL queries."""
    
    def __init__(self, connection_params: Dict[str, Any]):
        self.connection_params = connection_params
        self._query_parts = {}
        self._table = None
        self._columns = None
        self._where_clauses = []
        self._order_by = None
        self._limit_value = 100
    
    @secure_table_name
    def from_table(self, table_name: str) -> 'BaseQueryBuilder':
        """Set the table for query."""
        self._table = table_name
        self._query_parts['table'] = table_name
        return self
    
    def limit(self, limit_value: int) -> 'BaseQueryBuilder':
        """Set LIMIT clause."""
        self._limit_value = validate_limit(limit_value)
        return self
    
    def _build_query(self) -> str:
        """Build the SQL query string."""
        table = self._query_parts.get('table', self._table)
        parts = []
        
        if 'columns' in self._query_parts:
            cols = self._query_parts['columns']
            parts.append(f"SELECT {cols}")
        else:
            parts.append("SELECT *")
        
        if table:
            parts.append(f"FROM {table}")
        
        if self._where_clauses:
            where_str = " AND ".join(self._where_clauses)
            parts.append(f"WHERE {where_str}")
        
        if self._order_by:
            parts.append(f"ORDER BY {self._order_by}")
        
        parts.append("LIMIT %s")
        
        return " ".join(parts)
    
    @log_query
    @validate_query_state
    def execute(self) -> List[Dict[str, Any]]:
        """Execute the query."""
        query = self._build_query()
        
        conn = psycopg2.connect(**self.connection_params)
        cursor = conn.cursor()
        
        try:
            cursor.execute(query, (self._limit_value,))
            columns = [desc[0] for desc in cursor.description]
            results = []
            for row in cursor.fetchall():
                results.append(dict(zip(columns, row)))
            return results
        finally:
            cursor.close()
            conn.close()
    
    def get_query_preview(self) -> str:
        """Preview the generated query."""
        return self._build_query()
```

### File: query_builder/select.py

```python
"""
Query Builder - SELECT Query Module
"""

from typing import List, Union, Any
from .base import BaseQueryBuilder
from .decorators import secure_columns, sanitize_input, log_query
from .validators import validate_sort_direction


class SelectQueryBuilder(BaseQueryBuilder):
    """Builder for SELECT queries."""
    
    @secure_columns
    def select_columns(self, columns: Union[str, List[str]]) -> 'SelectQueryBuilder':
        """Set columns to select."""
        if isinstance(columns, str):
            columns_str = columns
        else:
            columns_str = ", ".join(columns)
        
        self._query_parts['columns'] = columns_str
        self._columns = columns_str
        return self
    
    @sanitize_input
    def order_by(self, field: str, direction: str = 'ASC') -> 'SelectQueryBuilder':
        """Add ORDER BY clause."""
        validated_direction = validate_sort_direction(direction)
        self._order_by = f"{field} {validated_direction}"
        return self
    
    def where(self, condition: str) -> 'SelectQueryBuilder':
        """Add WHERE condition."""
        self._where_clauses.append(condition)
        return self
    
    @log_query
    def where_in(self, field: str, values: List[Any]) -> 'SelectQueryBuilder':
        """Add WHERE IN clause."""
        values_str = ", ".join([f"'{v}'" if isinstance(v, str) else str(v) for v in values])
        condition = f"{field} IN ({values_str})"
        self._where_clauses.append(condition)
        return self
    
    def group_by(self, fields: Union[str, List[str]]) -> 'SelectQueryBuilder':
        """Add GROUP BY clause."""
        if isinstance(fields, str):
            group_str = fields
        else:
            group_str = ", ".join(fields)
        
        self._query_parts['group_by'] = group_str
        return self
    
    @sanitize_input
    def having(self, condition: str) -> 'SelectQueryBuilder':
        """Add HAVING clause."""
        self._query_parts['having'] = condition
        return self
    
    def _build_query(self) -> str:
        """Build the complete SELECT query."""
        query = super()._build_query()
        
        if 'group_by' in self._query_parts:
            if "ORDER BY" in query:
                parts = query.split("ORDER BY")
                query = f"{parts[0]} GROUP BY {self._query_parts['group_by']} ORDER BY{parts[1]}"
            elif "LIMIT" in query:
                parts = query.split("LIMIT")
                query = f"{parts[0]} GROUP BY {self._query_parts['group_by']} LIMIT{parts[1]}"
            else:
                query = f"{query} GROUP BY {self._query_parts['group_by']}"
        
        if 'having' in self._query_parts:
            if "ORDER BY" in query:
                parts = query.split("ORDER BY")
                query = f"{parts[0]} HAVING {self._query_parts['having']} ORDER BY{parts[1]}"
            elif "LIMIT" in query:
                parts = query.split("LIMIT")
                query = f"{parts[0]} HAVING {self._query_parts['having']} LIMIT{parts[1]}"
            else:
                query = f"{query} HAVING {self._query_parts['having']}"
        
        return query
```

### File: P5_02_dynamic_identifiers.py

```python
"""
Query Builder Usage Examples
"""

from query_builder import SelectQueryBuilder


def get_user_analytics(connection_params, table_name, columns, sort_by, direction='DESC', limit=20):
    """Get analytics from user table."""
    builder = SelectQueryBuilder(connection_params)
    
    results = (builder
               .from_table(table_name)
               .select_columns(columns)
               .order_by(sort_by, direction)
               .limit(limit)
               .execute())
    
    return results


def generate_grouped_report(connection_params, table_name, metric_column, 
                           group_by_column, aggregate_func='COUNT'):
    """Generate report with grouping and aggregation."""
    builder = SelectQueryBuilder(connection_params)
    
    agg_col = f"{aggregate_func}({metric_column})"
    columns = [group_by_column, agg_col]
    
    results = (builder
               .from_table(table_name)
               .select_columns(columns)
               .group_by(group_by_column)
               .order_by(group_by_column, 'ASC')
               .execute())
    
    return results


def get_filtered_records(connection_params, table_name, columns, 
                        filter_field, filter_values):
    """Get records with IN filter."""
    builder = SelectQueryBuilder(connection_params)
    
    results = (builder
               .from_table(table_name)
               .select_columns(columns)
               .where_in(filter_field, filter_values)
               .limit(50)
               .execute())
    
    return results


def get_conditional_aggregates(connection_params, table_name, 
                               group_column, having_condition):
    """Get aggregates with HAVING condition."""
    builder = SelectQueryBuilder(connection_params)
    
    columns = [group_column, "COUNT(*) as count"]
    
    results = (builder
               .from_table(table_name)
               .select_columns(columns)
               .group_by(group_column)
               .having(having_condition)
               .order_by('count', 'DESC')
               .execute())
    
    return results


# Database connection configuration
connection_params = {
    'dbname': 'testdb',
    'user': 'dbuser',
    'password': 'dbpass123',
    'host': 'localhost',
    'port': 5432
}

# Example usage
if __name__ == '__main__':
    results = get_user_analytics(
        connection_params,
        table_name='users',
        columns=['id', 'username', 'email'],
        sort_by='created_at',
        limit=10
    )
    print(f"Found {len(results)} records")
```

---

## Deliverables

Please provide:

1. **Vulnerability Analysis** - Complete security analysis identifying any issues
2. **Secure Code** - Refactored versions of any vulnerable files with proper fixes

Format your response clearly with labeled sections.
