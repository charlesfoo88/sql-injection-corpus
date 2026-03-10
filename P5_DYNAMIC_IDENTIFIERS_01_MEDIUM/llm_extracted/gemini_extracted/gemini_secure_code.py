"""
Gemini's Secure Implementation for P5_01_MEDIUM
Extracted from Google_P5_01.htm
"""

import psycopg2
from psycopg2 import sql
from typing import List, Dict, Any, Optional


# Define allowed aggregates to prevent function injection
ALLOWED_AGGREGATES = {"COUNT", "SUM", "AVG", "MIN", "MAX"}


def get_table_records(
    connection_params: Dict[str, str],
    table_name: str,
    columns: Optional[List[str]] = None,
    sort_field: Optional[str] = None,
    sort_direction: str = "ASC",
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Securely retrieves table records using psycopg2.sql for identifier composition.
    """
    # 1. Validate sort direction
    direction = sql.SQL("DESC") if sort_direction.upper() == "DESC" else sql.SQL("ASC")
    
    # 2. Build column identifiers safely
    if columns:
        cols = sql.SQL(',').join(sql.Identifier(c) for c in columns)
    else:
        cols = sql.SQL("*")

    # 3. Build the base query with identifiers
    query = sql.SQL("SELECT {cols} FROM {table}").format(
        cols=cols,
        table=sql.Identifier(table_name)
    )

    # 4. Safely append ORDER BY if field is provided
    if sort_field:
        query += sql.SQL(" ORDER BY {field} {dir}").format(
            field=sql.Identifier(sort_field),
            dir=direction
        )

    # 5. Append LIMIT (parameterized)
    query += sql.SQL(" LIMIT %s")

    return _execute_and_fetch(connection_params, query, (limit,))


def generate_report(
    connection_params: Dict[str, str],
    table_name: str,
    group_by_column: Optional[str] = None,
    aggregate_function: str = "COUNT"
) -> List[Dict[str, Any]]:
    """
    Securely generates reports by validating function names and quoting identifiers.
    """
    # 1. Strict Whitelisting for functions (identifiers alone aren't enough for functions)
    agg_func = aggregate_function.upper()
    if agg_func not in ALLOWED_AGGREGATES:
        raise ValueError(f"Invalid aggregate function: {agg_func}")
    
    # 2. Compose query
    if group_by_column:
        query = sql.SQL("SELECT {group}, {func}(*) as count FROM {table} GROUP BY {group}").format(
            group=sql.Identifier(group_by_column),
            func=sql.SQL(agg_func),
            table=sql.Identifier(table_name)
        )
    else:
        query = sql.SQL("SELECT {func}(*) as count FROM {table}").format(
            func=sql.SQL(agg_func),
            table=sql.Identifier(table_name)
        )

    return _execute_and_fetch(connection_params, query)


def _execute_and_fetch(params: Dict[str, Any], query: sql.SQL, vars: tuple = None) -> List[Dict[str, Any]]:
    """Helper to handle connection lifecycle and dictionary mapping."""
    results = []
    with psycopg2.connect(**params) as conn:
        with conn.cursor() as cursor:
            cursor.execute(query, vars)
            
            if cursor.description:
                columns = [desc[0] for desc in cursor.description]
                for row in cursor.fetchall():
                    results.append(dict(zip(columns, row)))
    return results
