"""
Query Builder - Base Module (SECURE VERSION)

This module provides the base query builder class with SQL injection protection
through identifier escaping and parameterized queries.
"""

import psycopg2
from typing import Dict, Any, Optional, List
from .decorators import secure_table_name, log_query, validate_query_state
from .validators import validate_limit, escape_identifier, validate_identifier


class BaseQueryBuilder:
    """
    Base class for building SQL queries with proper SQL injection protection.
    
    This class provides core functionality for query building with security features:
    - SQL identifier escaping for table/column names
    - Parameterized queries for values
    - Input validation
    - Query state management
    """
    
    def __init__(self, connection_params: Dict[str, Any]):
        """
        Initialize the query builder.
        
        Args:
            connection_params: Database connection parameters for psycopg2
        """
        self.connection_params = connection_params
        self._query_parts = {}
        self._table = None
        self._columns = None
        self._where_clauses = []
        self._where_params = []  # Store parameterized values
        self._order_by = None
        self._limit_value = 100
    
    @secure_table_name
    def from_table(self, table_name: str) -> 'BaseQueryBuilder':
        """
        Set the table for query with proper escaping.
        
        Args:
            table_name: Name of the table to query
            
        Returns:
            Self for method chaining
            
        Raises:
            ValueError: If table_name contains invalid characters
            
        Security:
            - Validates identifier format
            - Escapes table name to prevent SQL injection
        """
        # Validate the identifier
        if not validate_identifier(table_name):
            raise ValueError(f"Invalid table name: {table_name}")
        
        # Store escaped version
        self._table = escape_identifier(table_name)
        self._query_parts['table'] = self._table
        return self
    
    def limit(self, limit_value: int) -> 'BaseQueryBuilder':
        """
        Set LIMIT clause.
        
        Args:
            limit_value: Maximum number of rows to return (1-1000)
            
        Returns:
            Self for method chaining
            
        Raises:
            TypeError: If limit_value is not an integer
            ValueError: If limit_value is outside allowed range
        """
        self._limit_value = validate_limit(limit_value)
        return self
    
    def _build_query(self) -> str:
        """
        Build the SQL query string with properly escaped identifiers.
        
        Returns:
            The complete SQL query string with placeholders
            
        Note:
            All identifiers (table names, column names) are properly escaped.
            All values use parameterized placeholders (%s) to prevent injection.
        """
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
        """
        Execute the query with parameterized values.
        
        Returns:
            List of result rows as dictionaries
            
        Raises:
            ValueError: If query state is invalid
            psycopg2.Error: If database operation fails
            
        Security:
            - Uses parameterized queries for all values
            - Properly escapes all SQL identifiers
            - Validates query state before execution
        """
        query = self._build_query()
        
        conn = psycopg2.connect(**self.connection_params)
        cursor = conn.cursor()
        
        try:
            # Combine WHERE parameters with LIMIT
            params = tuple(self._where_params) + (self._limit_value,)
            cursor.execute(query, params)
            
            columns = [desc[0] for desc in cursor.description]
            results = []
            for row in cursor.fetchall():
                results.append(dict(zip(columns, row)))
            return results
        finally:
            cursor.close()
            conn.close()
    
    def get_query_preview(self) -> str:
        """
        Preview the generated query.
        
        Returns:
            The SQL query string with placeholders
            
        Warning:
            For debugging only - do not expose in production as it may
            reveal query structure to attackers.
        """
        return self._build_query()
