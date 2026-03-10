"""
Query Builder - SELECT Query Module (SECURE VERSION - ChatGPT)

Fixed using psycopg2.sql.Identifier() for all identifiers.
"""

from psycopg2 import sql
from typing import List, Any
from .base import BaseQueryBuilder


class SelectQueryBuilder(BaseQueryBuilder):
    
    def select_columns(self, columns: List[str]):
        self._columns = [sql.Identifier(c) for c in columns]
        return self
    
    def order_by(self, field: str, direction: str = "ASC"):
        self._order_by = sql.SQL("{} {}").format(
            sql.Identifier(field),
            sql.SQL(direction.upper())
        )
        return self
    
    def where_equals(self, field: str, value: Any):
        self._where.append(
            sql.SQL("{} = %s").format(sql.Identifier(field))
        )
        self._params.append(value)
        return self
    
    def where_in(self, field: str, values: List[Any]):
        placeholders = sql.SQL(", ").join(sql.Placeholder() * len(values))
        self._where.append(
            sql.SQL("{} IN ({})").format(
                sql.Identifier(field),
                placeholders
            )
        )
        self._params.extend(values)
        return self
    
    def group_by(self, fields: List[str]):
        self._group_by = [sql.Identifier(f) for f in fields]
        return self
    
    def having_count_gt(self, count: int):
        self._having = sql.SQL("COUNT(*) > %s")
        self._params.append(count)
        return self
