"""
Query Builder - Base Module

Provides the base query builder class with core functionality.

⚠️ CORE VULNERABILITY: Query assembly uses string formatting without sql.Identifier()!
"""

import psycopg2
from typing import Dict, Any, Optional, List
from .decorators import secure_table_name, log_query, validate_query_state
from .validators import validate_limit


class BaseQueryBuilder:
    """
    Base class for building SQL queries with fluent interface.
    
    ⚠️ VULNERABLE: All methods accumulate state in dictionary,
    final query built with string formatting in _build_query()!
    
    Vulnerability spread across multiple methods makes it hard to spot.
    """
    
    def __init__(self, connection_params: Dict[str, Any]):
        """
        Initialize query builder with database connection.
        
        Args:
            connection_params: PostgreSQL connection parameters
        """
        self.connection_params = connection_params
        self._query_parts = {}  # State accumulation
        self._table = None
        self._columns = None
        self._where_clauses = []
        self._order_by = None
        self._limit_value = 100
    
    @secure_table_name  # ⚠️ Decorator looks like security but isn't!
    def from_table(self, table_name: str) -> 'BaseQueryBuilder':
        """
        Set the table to query from.
        
        ⚠️ INJECTION POINT 1: Table name stored without proper quoting!
        
        Args:
            table_name: Name of the table (USER-CONTROLLED)
            
        Returns:
            Self for method chaining
        """
        # Decorator validates but doesn't sanitize
        self._table = table_name  # Stored as-is
        self._query_parts['table'] = table_name
        return self
    
    def limit(self, limit_value: int) -> 'BaseQueryBuilder':
        """
        Set the LIMIT for query results.
        
        ✅ SAFE: Properly validated and parameterized.
        
        Args:
            limit_value: Maximum number of rows to return
            
        Returns:
            Self for method chaining
        """
        # This one is actually safe - validated as integer
        self._limit_value = validate_limit(limit_value)
        return self
    
    def _build_query(self) -> str:
        """
        Build the final SQL query string.
        
        ⚠️ CORE VULNERABILITY: Uses f-strings without sql.Identifier()!
        
        This is where the injection happens - identifiers are formatted directly
        into the query string. Method chaining makes it hard to trace back to
        where user input was originally provided.
        
        Returns:
            SQL query string (VULNERABLE!)
        """
        # Get accumulated state
        table = self._query_parts.get('table', self._table)
        
        # Build query parts
        parts = []
        
        # SELECT clause (built by child classes)
        if 'columns' in self._query_parts:
            # ⚠️ VULNERABLE: Column names concatenated without quoting
            cols = self._query_parts['columns']
            parts.append(f"SELECT {cols}")
        else:
            parts.append("SELECT *")
        
        # FROM clause
        # ⚠️ VULNERABLE: Table name formatted directly
        if table:
            parts.append(f"FROM {table}")
        
        # WHERE clause (if built by subclasses)
        if self._where_clauses:
            where_str = " AND ".join(self._where_clauses)
            parts.append(f"WHERE {where_str}")
        
        # ORDER BY clause (if set)
        if self._order_by:
            # ⚠️ VULNERABLE: Sort field formatted directly
            parts.append(f"ORDER BY {self._order_by}")
        
        # LIMIT clause (safe - parameterized later)
        parts.append("LIMIT %s")
        
        # Join all parts
        query = " ".join(parts)
        
        return query
    
    @log_query  # Just logs, doesn't prevent injection
    @validate_query_state  # Checks state exists, not safety
    def execute(self) -> List[Dict[str, Any]]:
        """
        Execute the built query and return results.
        
        ⚠️ EXECUTION POINT: Vulnerable query executed here!
        
        Returns:
            List of result rows as dictionaries
        """
        # Build the vulnerable query
        query = self._build_query()
        
        conn = psycopg2.connect(**self.connection_params)
        cursor = conn.cursor()
        
        try:
            # Execute with only limit parameterized
            # Identifiers already formatted into query string
            cursor.execute(query, (self._limit_value,))
            
            # Fetch results
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
        Get preview of query that will be executed.
        
        Useful for debugging but exposes the vulnerability.
        
        Returns:
            Query string with %s placeholder for limit
        """
        return self._build_query()
