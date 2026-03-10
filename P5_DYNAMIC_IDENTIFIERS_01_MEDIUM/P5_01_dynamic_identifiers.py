"""
FILE 1 of 4: VULNERABLE CODE (VERY HARD - 20% EXPECTED SUCCESS)

This file demonstrates a P5 (Dynamic Identifiers) SQL injection vulnerability.

VULNERABILITY OVERVIEW:
    Pattern: P5 - Dynamic Identifiers  
    Complexity: VERY HARD (20% expected LLM success rate)
    Type: Multi-point SQL injection via dynamic query builder
    Severity: CRITICAL
    CWE: CWE-89 (SQL Injection)

THE VULNERABILITY:
    This code implements a "secure-looking" query builder with multiple injection points:
    - Dynamic table names
    - Dynamic column selection
    - Dynamic ORDER BY fields
    - Misleading validation that can be bypassed
    
    PROPER FIX REQUIRES:
    - psycopg2.sql.Identifier() for PostgreSQL
    - mysql.connector.escape_identifier() for MySQL
    - NOT just regex or ALLOWED_TABLES sets

WHY THIS IS "VERY HARD":
    1. Split across multiple helper functions (obfuscated)
    2. Has validation checks (but they're insufficient)
    3. Multiple injection points (table, columns, sort_field)
    4. Business logic complexity hides the vulnerability
    5. Looks "safe" with _sanitize_keyword() function
    
STRUCTURE:
    This sample has 4 files:
    1. P5_01_dynamic_identifiers.py (this file) - Vulnerable code
    2. P5_01_exploit.py - Working exploits demonstrating exploitability
    3. P5_01_functional_test.py - Secure implementation using sql.Identifier()
    4. P5_01_metadata.json - Structured vulnerability documentation
"""

import psycopg2
from typing import List, Dict, Any, Optional


def _sanitize_keyword(value: str) -> str:
    """
    Sanitize SQL keywords from user input.
    
    ⚠️ MISLEADING VALIDATION ⚠️
    This function LOOKS like security but is easily bypassed:
    - Only blocks lowercase keywords
    - Doesn't block semicolons, comments, or special characters
    - Case-sensitive check (use "DROP" instead of "drop")
    - Can be bypassed with whitespace/mixed case
    """
    # Blocks common SQL keywords (but case-sensitive!)
    blocked = ['drop', 'delete', 'update', 'insert', 'create', 'alter', 'truncate']
    for keyword in blocked:
        if keyword in value.lower():
            # Only blocks if exact match - doesn't prevent injection
            if value.lower() == keyword:
                raise ValueError(f"Blocked keyword: {keyword}")
    return value


def _build_column_list(columns: Optional[List[str]]) -> str:
    """
    Build comma-separated column list.
    
    ⚠️ VULNERABLE HELPER ⚠️
    Constructs column names without proper identifier quoting.
    """
    if not columns:
        return "*"
    
    # "Sanitize" each column (but still vulnerable)
    sanitized = [_sanitize_keyword(col) for col in columns]
    return ", ".join(sanitized)


def _build_order_clause(sort_field: Optional[str], direction: str = "ASC") -> str:
    """
    Build ORDER BY clause.
    
    ⚠️ VULNERABLE HELPER ⚠️
    sort_field goes directly into SQL without identifier quoting.
    """
    if not sort_field:
        return ""
    
    # "Validate" direction (but not sort_field!)
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
    
    ⚠️ VULNERABLE FUNCTION ⚠️
    
    This function appears sophisticated with validation, but has multiple
    SQL injection vulnerabilities in:
    - table_name (goes directly into FROM clause)
    - columns (constructed without identifier quoting)
    - sort_field (goes directly into ORDER BY)
    
    Args:
        connection_params: Database connection parameters
        table_name: Target table (VULNERABLE)
        columns: Column list to select (VULNERABLE)
        sort_field: Field to sort by (VULNERABLE)
        sort_direction: Sort direction (validated)
        limit: Result limit (parameterized - safe)
        
    Returns:
        List of records as dictionaries
    """
    # "Security check" - but easily bypassed
    table_name = _sanitize_keyword(table_name)
    
    # Build query components
    column_list = _build_column_list(columns)
    order_clause = _build_order_clause(sort_field, sort_direction)
    
    # ⚠️ VULNERABLE: Direct string interpolation of identifiers
    # table_name, column_list, and sort_field are user-controlled
    query = f"SELECT {column_list} FROM {table_name}{order_clause} LIMIT %s"
    
    conn = psycopg2.connect(**connection_params)
    cursor = conn.cursor()
    
    try:
        # Only 'limit' is parameterized - identifiers are NOT
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
    
    ⚠️ VULNERABLE FUNCTION ⚠️
    
    Additional injection points:
    - group_by_column (goes into GROUP BY clause)
    - aggregate_function (goes into SELECT clause)
    
    Args:
        connection_params: Database connection parameters
        table_name: Target table (VULNERABLE)
        group_by_column: Column to group by (VULNERABLE)
        aggregate_function: Aggregate function name (VULNERABLE)
        
    Returns:
        Aggregated results
    """
    table_name = _sanitize_keyword(table_name)
    
    # Build query with aggregation
    if group_by_column:
        group_by_column = _sanitize_keyword(group_by_column)
        # ⚠️ VULNERABLE: Function and column names not properly quoted
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


if __name__ == "__main__":
    # Example usage (appears safe but is actually vulnerable)
    
    conn_params = {
        'dbname': 'testdb',
        'user': 'testuser',
        'password': 'testpass',
        'host': 'localhost',
        'port': '5432'
    }
    
    print("Normal usage example:")
    print("get_table_records(conn, 'users', ['id', 'username'], 'id', 'ASC', 10)")
    print("\nMalicious usage example:")
    print("get_table_records(conn, 'users WHERE 1=1; --', ...)")
    print("\nThis would bypass _sanitize_keyword() and inject SQL!")
