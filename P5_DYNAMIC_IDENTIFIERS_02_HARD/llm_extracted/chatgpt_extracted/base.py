"""
Query Builder - Base Module (SECURE VERSION - ChatGPT)

Fixed using psycopg2.sql.Identifier() for all identifiers.
"""

from psycopg2 import sql
import psycopg2
from typing import Dict, Any, List


class BaseQueryBuilder:
    def __init__(self, connection_params: Dict[str, Any]):
        self.connection_params = connection_params
        self._table = None
        self._columns = []
        self._where = []
        self._params = []
        self._order_by = None
        self._limit = None
        self._group_by = []
        self._having = None
    
    def from_table(self, table_name: str) -> 'BaseQueryBuilder':
        self._table = sql.Identifier(table_name)
        return self
    
    def limit(self, limit: int) -> 'BaseQueryBuilder':
        self._limit = limit
        return self
    
    def _build_query(self) -> sql.SQL:
        query = sql.SQL("SELECT {cols} FROM {table}").format(
            cols=sql.SQL(", ").join(self._columns) if self._columns else sql.SQL("*"),
            table=self._table
        )
        
        if self._where:
            query += sql.SQL(" WHERE ") + sql.SQL(" AND ").join(self._where)
        
        if self._group_by:
            query += sql.SQL(" GROUP BY ") + sql.SQL(", ").join(self._group_by)
        
        if self._having:
            query += sql.SQL(" HAVING ") + self._having
        
        if self._order_by:
            query += sql.SQL(" ORDER BY ") + self._order_by
        
        if self._limit:
            query += sql.SQL(" LIMIT %s")
            self._params.append(self._limit)
        
        return query
    
    def execute(self) -> List[Dict[str, Any]]:
        query = self._build_query()
        with psycopg2.connect(**self.connection_params) as conn:
            with conn.cursor() as cur:
                cur.execute(query, self._params)
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, row)) for row in cur.fetchall()]
