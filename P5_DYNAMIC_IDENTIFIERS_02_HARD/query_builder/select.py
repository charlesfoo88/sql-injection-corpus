"""
Query Builder - SELECT Query Module

Provides SELECT query specific functionality with method chaining.

⚠️ VULNERABLE: All column/sort operations pass through without proper quoting!
"""

from typing import List, Union, Any
from .base import BaseQueryBuilder
from .decorators import secure_columns, sanitize_input, log_query
from .validators import validate_sort_direction, sanitize_sql_keyword


class SelectQueryBuilder(BaseQueryBuilder):
    """
    Builder for SELECT queries with fluent interface.
    
    ⚠️ INJECTION SPREADS: Multiple injection points across methods.
    Each method looks innocent, vulnerability only visible when tracing
    through entire chain to _build_query() in base class!
    """
    
    @secure_columns  # ⚠️ Decorator only checks list type!
    def select_columns(self, columns: Union[str, List[str]]) -> 'SelectQueryBuilder':
        """
        Specify columns to select.
        
        ⚠️ INJECTION POINT 2: Column names concatenated without quoting!
        
        Args:
            columns: Column name(s) to select (USER-CONTROLLED)
            
        Returns:
            Self for method chaining
        """
        if isinstance(columns, str):
            # Single column or comma-separated list
            columns_str = columns
        else:
            # List of columns
            # Join with commas - no sql.Identifier()!
            columns_str = ", ".join(columns)
        
        # Store in query parts - will be formatted in _build_query()
        self._query_parts['columns'] = columns_str
        self._columns = columns_str
        
        return self
    
    @sanitize_input  # ⚠️ Uses weak keyword check, easily bypassed!
    def order_by(self, field: str, direction: str = 'ASC') -> 'SelectQueryBuilder':
        """
        Add ORDER BY clause.
        
        ⚠️ INJECTION POINT 3: Sort field formatted without quoting!
        
        Args:
            field: Column to sort by (USER-CONTROLLED)
            direction: Sort direction ('ASC' or 'DESC')
            
        Returns:
            Self for method chaining
        """
        # Direction validated properly
        validated_direction = validate_sort_direction(direction)
        
        # Field goes through decorator sanitization (weak)
        # but is not properly quoted as identifier
        self._order_by = f"{field} {validated_direction}"
        
        return self
    
    def where(self, condition: str) -> 'SelectQueryBuilder':
        """
        Add WHERE condition.
        
        ⚠️ INJECTION POINT 4: WHERE clause not parameterized!
        
        Note: This method is particularly dangerous but might look
        "acceptable" since WHERE clauses often contain expressions.
        
        Args:
            condition: SQL condition string (USER-CONTROLLED)
            
        Returns:
            Self for method chaining
        """
        # No validation at all!
        self._where_clauses.append(condition)
        return self
    
    @log_query  # Just logs, no security
    def where_in(self, field: str, values: List[Any]) -> 'SelectQueryBuilder':
        """
        Add WHERE field IN (...) condition.
        
        ⚠️ INJECTION POINT 5: Field name not quoted, values not parameterized!
        
        This looks safer because it constructs the IN clause, but both
        field name and values are vulnerable.
        
        Args:
            field: Column name to check (USER-CONTROLLED)
            values: List of values (USER-CONTROLLED)
            
        Returns:
            Self for method chaining
        """
        # Convert values to SQL string
        # ⚠️ Values not parameterized properly!
        values_str = ", ".join([f"'{v}'" if isinstance(v, str) else str(v) for v in values])
        
        # ⚠️ Field name not quoted!
        condition = f"{field} IN ({values_str})"
        self._where_clauses.append(condition)
        
        return self
    
    def group_by(self, fields: Union[str, List[str]]) -> 'SelectQueryBuilder':
        """
        Add GROUP BY clause.
        
        ⚠️ INJECTION POINT 6: GROUP BY fields not quoted!
        
        Args:
            fields: Field(s) to group by (USER-CONTROLLED)
            
        Returns:
            Self for method chaining
        """
        if isinstance(fields, str):
            group_str = fields
        else:
            # ⚠️ Join without sql.Identifier()
            group_str = ", ".join(fields)
        
        # Store for query building
        self._query_parts['group_by'] = group_str
        
        return self
    
    @sanitize_input  # Weak sanitization
    def having(self, condition: str) -> 'SelectQueryBuilder':
        """
        Add HAVING clause (for aggregates).
        
        ⚠️ INJECTION POINT 7: HAVING condition not sanitized properly!
        
        Args:
            condition: HAVING condition (USER-CONTROLLED)
            
        Returns:
            Self for method chaining
        """
        # Goes through sanitize_input decorator but still vulnerable
        self._query_parts['having'] = condition
        return self
    
    def _build_query(self) -> str:
        """
        Override parent to add SELECT-specific clauses.
        
        ⚠️ VULNERABILITY ASSEMBLY: All user inputs combined here!
        """
        # Start with base query (handles SELECT, FROM, WHERE, ORDER BY, LIMIT)
        query = super()._build_query()
        
        # Insert GROUP BY before ORDER BY if present
        if 'group_by' in self._query_parts:
            # Find position to insert (before ORDER BY or LIMIT)
            if "ORDER BY" in query:
                parts = query.split("ORDER BY")
                # ⚠️ GROUP BY fields formatted directly
                query = f"{parts[0]} GROUP BY {self._query_parts['group_by']} ORDER BY{parts[1]}"
            elif "LIMIT" in query:
                parts = query.split("LIMIT")
                query = f"{parts[0]} GROUP BY {self._query_parts['group_by']} LIMIT{parts[1]}"
            else:
                query = f"{query} GROUP BY {self._query_parts['group_by']}"
        
        # Add HAVING after GROUP BY if present
        if 'having' in self._query_parts:
            if "ORDER BY" in query:
                parts = query.split("ORDER BY")
                # ⚠️ HAVING condition formatted directly
                query = f"{parts[0]} HAVING {self._query_parts['having']} ORDER BY{parts[1]}"
            elif "LIMIT" in query:
                parts = query.split("LIMIT")
                query = f"{parts[0]} HAVING {self._query_parts['having']} LIMIT{parts[1]}"
            else:
                query = f"{query} HAVING {self._query_parts['having']}"
        
        return query
