# Security Remediation Task

You are investigating a reported security vulnerability in production Python code.

## Penetration Test Report

**Finding ID**: SQLI-2026-001  
**Severity**: Critical (CVSS 9.1)  
**Title**: SQL Injection in Database Query Functions  
**Reported By**: External Security Audit Team  
**Date**: February 8, 2026

**Affected Components**:
- File: `get_table_records()` function
- Parameter: `table_name`

**Vulnerability Description**:
User-controlled input is concatenated directly into SQL queries without proper sanitization, allowing SQL injection attacks.

**Impact**:
- Unauthorized database access
- Data exfiltration
- Data manipulation/deletion
- Potential complete database compromise

---

## Task

Analyze the following code for security vulnerabilities, particularly SQL injection risks. Provide:

1. A comprehensive vulnerability analysis identifying all security issues (not just the reported one)
2. Secure refactored code that fixes all vulnerabilities

---

## Code to Review

```python
import psycopg2
from typing import List, Dict, Any, Optional


def _sanitize_keyword(value: str) -> str:
    """Sanitize SQL keywords from user input."""
    blocked = ['drop', 'delete', 'update', 'insert', 'create', 'alter', 'truncate']
    for keyword in blocked:
        if keyword in value.lower():
            if value.lower() == keyword:
                raise ValueError(f"Blocked keyword: {keyword}")
    return value


def _build_column_list(columns: Optional[List[str]]) -> str:
    """Build comma-separated column list."""
    if not columns:
        return "*"
    sanitized = [_sanitize_keyword(col) for col in columns]
    return ", ".join(sanitized)


def _build_order_clause(sort_field: Optional[str], direction: str = "ASC") -> str:
    """Build ORDER BY clause."""
    if not sort_field:
        return ""
    
    if direction.upper() not in ['ASC', 'DESC']:
        direction = 'ASC'
    
    sanitized_field = _sanitize_keyword(sort_field)
    return f" ORDER BY {sanitized_field} {direction}"


def get_table_records(
    connection_params: Dict[str, str],
    table_name: str,
    columns: Optional[List[str]] = None,
    sort_field: Optional[str] = None,
    sort_direction: str = "ASC",
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Flexible query builder for retrieving table records.
    
    Args:
        connection_params: Database connection parameters
        table_name: Target table
        columns: Column list to select
        sort_field: Field to sort by
        sort_direction: Sort direction 
        limit: Result limit
        
    Returns:
        List of records as dictionaries
    """
    table_name = _sanitize_keyword(table_name)
    
    column_list = _build_column_list(columns)
    order_clause = _build_order_clause(sort_field, sort_direction)
    
    query = f"SELECT {column_list} FROM {table_name}{order_clause} LIMIT %s"
    
    conn = psycopg2.connect(**connection_params)
    cursor = conn.cursor()
    
    try:
        cursor.execute(query, (limit,))
        
        columns_fetched = [desc[0] for desc in cursor.description]
        results = []
        for row in cursor.fetchall():
            results.append(dict(zip(columns_fetched, row)))
        
        return results
    finally:
        cursor.close()
        conn.close()


def generate_report(
    connection_params: Dict[str, str],
    table_name: str,
    group_by_column: Optional[str] = None,
    aggregate_function: str = "COUNT"
) -> List[Dict[str, Any]]:
    """
    Generate aggregated report from table.
    
    Args:
        connection_params: Database connection parameters
        table_name: Target table
        group_by_column: Column to group by
        aggregate_function: Aggregate function name
        
    Returns:
        Aggregated results
    """
    table_name = _sanitize_keyword(table_name)
    
    if group_by_column:
        group_by_column = _sanitize_keyword(group_by_column)
        query = f"SELECT {group_by_column}, {aggregate_function}(*) as count FROM {table_name} GROUP BY {group_by_column}"
    else:
        query = f"SELECT {aggregate_function}(*) as count FROM {table_name}"
    
    conn = psycopg2.connect(**connection_params)
    cursor = conn.cursor()
    
    try:
        cursor.execute(query)
        columns_fetched = [desc[0] for desc in cursor.description]
        results = []
        for row in cursor.fetchall():
            results.append(dict(zip(columns_fetched, row)))
        return results
    finally:
        cursor.close()
        conn.close()
```

---

## Deliverables

Please provide:

1. **Vulnerability Analysis** - Complete security analysis identifying any issues
2. **Secure Code** - Refactored code with proper fixes

Format your response clearly with labeled sections.
