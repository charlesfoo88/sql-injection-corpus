"""
Query Builder - SELECT Query Module (SECURE VERSION)

This module provides the SELECT query builder with comprehensive SQL injection protection.
"""

from typing import List, Union, Any
from .base import BaseQueryBuilder
from .decorators import secure_columns, sanitize_input, log_query
from .validators import validate_sort_direction, escape_identifier, validate_identifier


class SelectQueryBuilder(BaseQueryBuilder):
    """
    Builder for SELECT queries with SQL injection protection.
    
    This class extends BaseQueryBuilder with SELECT-specific functionality:
    - Column selection with proper escaping
    - WHERE clauses using parameterized queries
    - ORDER BY with escaped identifiers
    - GROUP BY and HAVING with security controls
    """
    
    @secure_columns
    def select_columns(self, columns: Union[str, List[str]]) -> 'SelectQueryBuilder':
        """
        Set columns to select with proper escaping.
        
        Args:
            columns: Single column name (str) or list of column names
            
        Returns:
            Self for method chaining
            
        Raises:
            ValueError: If any column name is invalid
            
        Security:
            - Validates each column name format
            - Escapes all column names to prevent injection
            
        Example:
            >>> builder.select_columns(['id', 'username', 'email'])
            >>> builder.select_columns('user_id')
        """
        if isinstance(columns, str):
            # Single column
            if not validate_identifier(columns):
                raise ValueError(f"Invalid column name: {columns}")
            columns_str = escape_identifier(columns)
        else:
            # Multiple columns - validate and escape each
            escaped_columns = []
            for col in columns:
                if not validate_identifier(col):
                    raise ValueError(f"Invalid column name: {col}")
                escaped_columns.append(escape_identifier(col))
            columns_str = ", ".join(escaped_columns)
        
        self._query_parts['columns'] = columns_str
        self._columns = columns_str
        return self
    
    @sanitize_input
    def order_by(self, field: str, direction: str = 'ASC') -> 'SelectQueryBuilder':
        """
        Add ORDER BY clause with proper escaping.
        
        Args:
            field: Field name to sort by
            direction: Sort direction ('ASC' or 'DESC')
            
        Returns:
            Self for method chaining
            
        Raises:
            ValueError: If field name is invalid or direction is not ASC/DESC
            
        Security:
            - Validates field name format
            - Escapes field identifier
            - Whitelists only ASC/DESC for direction
            
        Example:
            >>> builder.order_by('created_at', 'DESC')
        """
        # Validate field name
        if not validate_identifier(field):
            raise ValueError(f"Invalid field name for ORDER BY: {field}")
        
        # Validate direction using whitelist
        validated_direction = validate_sort_direction(direction)
        
        # Escape the field identifier
        escaped_field = escape_identifier(field)
        self._order_by = f"{escaped_field} {validated_direction}"
        return self
    
    def where(self, field: str, operator: str, value: Any) -> 'SelectQueryBuilder':
        """
        Add WHERE condition using parameterized queries.
        
        Args:
            field: Field name to filter on
            operator: Comparison operator (=, !=, <, >, <=, >=, LIKE, ILIKE)
            value: Value to compare against (will be parameterized)
            
        Returns:
            Self for method chaining
            
        Raises:
            ValueError: If field name or operator is invalid
            
        Security:
            - Validates and escapes field name
            - Whitelists allowed operators
            - Uses parameterized query for value (prevents injection)
            
        Example:
            >>> builder.where('status', '=', 'active')
            >>> builder.where('age', '>', 18)
        """
        # Validate field name
        if not validate_identifier(field):
            raise ValueError(f"Invalid field name: {field}")
        
        # Whitelist allowed operators
        allowed_operators = ['=', '!=', '<', '>', '<=', '>=', 'LIKE', 'ILIKE']
        if operator not in allowed_operators:
            raise ValueError(f"Invalid operator: {operator}. Allowed: {allowed_operators}")
        
        # Use parameterized query
        escaped_field = escape_identifier(field)
        placeholder = "%s"
        condition = f"{escaped_field} {operator} {placeholder}"
        
        self._where_clauses.append(condition)
        self._where_params.append(value)
        return self
    
    @log_query
    def where_in(self, field: str, values: List[Any]) -> 'SelectQueryBuilder':
        """
        Add WHERE IN clause with parameterized queries.
        
        Args:
            field: Field name to filter on
            values: List of values for IN clause
            
        Returns:
            Self for method chaining
            
        Raises:
            ValueError: If field name is invalid or values is empty
            
        Security:
            - Validates and escapes field name
            - Uses parameterized placeholders for all values
            - Prevents injection through proper parameterization
            
        Example:
            >>> builder.where_in('status', ['active', 'pending', 'approved'])
        """
        # Validate field name
        if not validate_identifier(field):
            raise ValueError(f"Invalid field name: {field}")
        
        if not values:
            raise ValueError("WHERE IN requires at least one value")
        
        # Create parameterized placeholders
        escaped_field = escape_identifier(field)
        placeholders = ", ".join(["%s"] * len(values))
        condition = f"{escaped_field} IN ({placeholders})"
        
        self._where_clauses.append(condition)
        self._where_params.extend(values)
        return self
    
    def group_by(self, fields: Union[str, List[str]]) -> 'SelectQueryBuilder':
        """
        Add GROUP BY clause with proper escaping.
        
        Args:
            fields: Single field name or list of field names to group by
            
        Returns:
            Self for method chaining
            
        Raises:
            ValueError: If any field name is invalid
            
        Security:
            - Validates each field name format
            - Escapes all field identifiers
            
        Example:
            >>> builder.group_by('category')
            >>> builder.group_by(['department', 'status'])
        """
        if isinstance(fields, str):
            # Single field
            if not validate_identifier(fields):
                raise ValueError(f"Invalid field name: {fields}")
            group_str = escape_identifier(fields)
        else:
            # Multiple fields
            escaped_fields = []
            for field in fields:
                if not validate_identifier(field):
                    raise ValueError(f"Invalid field name: {field}")
                escaped_fields.append(escape_identifier(field))
            group_str = ", ".join(escaped_fields)
        
        self._query_parts['group_by'] = group_str
        return self
    
    def having(self, field: str, operator: str, value: Any) -> 'SelectQueryBuilder':
        """
        Add HAVING clause with parameterized queries.
        
        Args:
            field: Field name or aggregate function result to filter on
            operator: Comparison operator (=, !=, <, >, <=, >=)
            value: Value to compare against (will be parameterized)
            
        Returns:
            Self for method chaining
            
        Raises:
            ValueError: If field name or operator is invalid
            
        Security:
            - Validates and escapes field name
            - Whitelists allowed operators
            - Uses parameterized query for value
            
        Note:
            For aggregate functions, the field should match what's in SELECT
            
        Example:
            >>> builder.having('count', '>', 5)
        """
        # Validate field/function
        if not validate_identifier(field):
            raise ValueError(f"Invalid field name for HAVING: {field}")
        
        # Whitelist allowed operators
        allowed_operators = ['=', '!=', '<', '>', '<=', '>=']
        if operator not in allowed_operators:
            raise ValueError(f"Invalid operator: {operator}")
        
        # Use parameterized query
        escaped_field = escape_identifier(field)
        having_condition = f"{escaped_field} {operator} %s"
        
        self._query_parts['having'] = having_condition
        self._where_params.append(value)  # HAVING params go with WHERE params
        return self
    
    def _build_query(self) -> str:
        """
        Build the complete SELECT query with escaped identifiers.
        
        Returns:
            Complete SQL query string with placeholders
            
        Note:
            All identifiers are properly escaped and all values use
            parameterized placeholders.
        """
        query = super()._build_query()
        
        if 'group_by' in self._query_parts:
            if "ORDER BY" in query:
                parts = query.split("ORDER BY")
                query = f"{parts[0]} GROUP BY {self._query_parts['group_by']} ORDER BY{parts[1]}"
            elif "LIMIT" in query:
                parts = query.split("LIMIT")
                query = f"{parts[0]} GROUP BY {self._query_parts['group_by']} LIMIT{parts[1]}"
            else:
                query = f"{query} GROUP BY {self._query_parts['group_by']}"
        
        if 'having' in self._query_parts:
            if "ORDER BY" in query:
                parts = query.split("ORDER BY")
                query = f"{parts[0]} HAVING {self._query_parts['having']} ORDER BY{parts[1]}"
            elif "LIMIT" in query:
                parts = query.split("LIMIT")
                query = f"{parts[0]} HAVING {self._query_parts['having']} LIMIT{parts[1]}"
            else:
                query = f"{query} HAVING {self._query_parts['having']}"
        
        return query
