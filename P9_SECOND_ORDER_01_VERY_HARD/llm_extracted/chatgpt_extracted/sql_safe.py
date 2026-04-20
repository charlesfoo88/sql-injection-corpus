"""
ChatGPT's Secure SQL Helpers for P9_01
Extracted from OpenAI P09_01.htm
"""

ALLOWED_COLUMNS = {
    'id': 'id',
    'username': 'username',
    'email': 'email',
    'department': 'department',
    'role': 'role',
    'salary': 'salary',
    'age': 'age',
    'status': 'status',
    'country': 'country',
    'city': 'city',
    'created_at': 'created_at'
}

ALLOWED_AGGREGATES = {
    'COUNT': 'COUNT',
    'SUM': 'SUM',
    'AVG': 'AVG',
    'MIN': 'MIN',
    'MAX': 'MAX'
}

def safe_column(name: str) -> str:
    if name not in ALLOWED_COLUMNS:
        raise ValueError("Invalid column")
    return ALLOWED_COLUMNS[name]

def safe_aggregate(name: str) -> str:
    if name not in ALLOWED_AGGREGATES:
        raise ValueError("Invalid aggregate")
    return ALLOWED_AGGREGATES[name]
