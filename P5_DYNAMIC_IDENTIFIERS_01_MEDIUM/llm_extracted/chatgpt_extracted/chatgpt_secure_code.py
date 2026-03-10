"""
ChatGPT's Secure Implementation for P5_01_MEDIUM
Extracted from OpenAI P5_01.htm
"""

import psycopg2
from psycopg2 import sql
from typing import List, Dict, Any, Optional


# Explicit allowlists (should ideally come from config or schema inspection)
ALLOWED_TABLES = {"users", "orders", "products"}
ALLOWED_AGGREGATES = {"COUNT", "SUM", "AVG", "MIN", "MAX"}
MAX_LIMIT = 1000


def _validate_identifier(name: str, allowed: set) -> str:
    if name not in allowed:
        raise ValueError(f"Invalid identifier: {name}")
    return name


def get_table_records(
    connection_params: Dict[str, str],
    table_name: str,
    columns: Optional[List[str]] = None,
    sort_field: Optional[str] = None,
    sort_direction: str = "ASC",
    limit: int = 100
) -> List[Dict[str, Any]]:

    if limit < 1 or limit > MAX_LIMIT:
        raise ValueError("Invalid limit")

    table_name = _validate_identifier(table_name, ALLOWED_TABLES)

    if columns:
        column_identifiers = [sql.Identifier(col) for col in columns]
    else:
        column_identifiers = [sql.SQL("*")]

    order_clause = sql.SQL("")
    if sort_field:
        direction = sort_direction.upper()
        if direction not in ("ASC", "DESC"):
            raise ValueError("Invalid sort direction")
        order_clause = sql.SQL(" ORDER BY {} {}").format(
            sql.Identifier(sort_field),
            sql.SQL(direction)
        )

    query = sql.SQL("SELECT {} FROM {}{} LIMIT %s").format(
        sql.SQL(", ").join(column_identifiers),
        sql.Identifier(table_name),
        order_clause
    )

    with psycopg2.connect(**connection_params) as conn:
        with conn.cursor() as cursor:
            cursor.execute(query, (limit,))
            cols = [desc[0] for desc in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]


def generate_report(
    connection_params: Dict[str, str],
    table_name: str,
    group_by_column: Optional[str] = None,
    aggregate_function: str = "COUNT"
) -> List[Dict[str, Any]]:

    table_name = _validate_identifier(table_name, ALLOWED_TABLES)
    aggregate_function = aggregate_function.upper()

    if aggregate_function not in ALLOWED_AGGREGATES:
        raise ValueError("Invalid aggregate function")

    agg_sql = sql.SQL(aggregate_function)

    if group_by_column:
        query = sql.SQL(
            "SELECT {group_col}, {agg}(*) AS count FROM {table} GROUP BY {group_col}"
        ).format(
            group_col=sql.Identifier(group_by_column),
            agg=agg_sql,
            table=sql.Identifier(table_name)
        )
    else:
        query = sql.SQL(
            "SELECT {agg}(*) AS count FROM {table}"
        ).format(
            agg=agg_sql,
            table=sql.Identifier(table_name)
        )

    with psycopg2.connect(**connection_params) as conn:
        with conn.cursor() as cursor:
            cursor.execute(query)
            cols = [desc[0] for desc in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
