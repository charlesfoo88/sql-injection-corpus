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
