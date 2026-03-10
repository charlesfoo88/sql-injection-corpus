"""
Secure Database Query Module - Refactored Version

This module provides secure database query functions with comprehensive
SQL injection protection using allowlist validation and proper parameterization.

Security Features:
- Allowlist-based identifier validation
- SQL identifier quoting for table/column names
- Parameterized queries for all values
- Connection pooling support
- Comprehensive error handling
- Audit logging
- Input validation

Author: Security Review Team
Date: February 10, 2026
Version: 2.0.0 (Security Hardened)
"""

import psycopg2
from psycopg2 import sql, pool
from typing import List, Dict, Any, Optional, Set
import logging
from contextlib import contextmanager
from datetime import datetime


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatabaseQueryError(Exception):
    """Custom exception for database query errors."""
    pass


class SecurityValidationError(Exception):
    """Custom exception for security validation failures."""
    pass


class SecureQueryBuilder:
    """
    Secure query builder with SQL injection protection.
    
    Security Controls:
    1. Allowlist validation for all identifiers
    2. SQL identifier quoting via psycopg2.sql
    3. Parameterized queries for all values
    4. Comprehensive input validation
    5. Audit logging
    """
    
    # Allowlists for valid identifiers (should be loaded from config in production)
    VALID_TABLES: Set[str] = {
        'users', 'products', 'orders', 'customers', 
        'inventory', 'categories', 'transactions'
    }
    
    VALID_COLUMNS: Dict[str, Set[str]] = {
        'users': {'id', 'username', 'email', 'created_at', 'role', 'status'},
        'products': {'id', 'name', 'category', 'price', 'stock', 'created_at'},
        'orders': {'id', 'user_id', 'product_id', 'quantity', 'total', 'created_at'},
        'customers': {'id', 'name', 'email', 'phone', 'address', 'created_at'},
        'inventory': {'id', 'product_id', 'quantity', 'warehouse', 'updated_at'},
        'categories': {'id', 'name', 'description', 'parent_id'},
        'transactions': {'id', 'order_id', 'amount', 'status', 'created_at'}
    }
    
    VALID_AGGREGATE_FUNCTIONS: Set[str] = {
        'COUNT', 'SUM', 'AVG', 'MIN', 'MAX'
    }
    
    VALID_SORT_DIRECTIONS: Set[str] = {'ASC', 'DESC'}
    
    def __init__(self, connection_pool: pool.SimpleConnectionPool):
        """
        Initialize secure query builder.
        
        Args:
            connection_pool: psycopg2 connection pool
        """
        self.connection_pool = connection_pool
    
    @staticmethod
    def _validate_table_name(table_name: str) -> str:
        """
        Validate table name against allowlist.
        
        Args:
            table_name: Table name to validate
            
        Returns:
            Validated table name
            
        Raises:
            SecurityValidationError: If table name is invalid
        """
        if not table_name:
            raise SecurityValidationError("Table name cannot be empty")
        
        # Convert to lowercase for case-insensitive comparison
        table_name_lower = table_name.lower().strip()
        
        if table_name_lower not in SecureQueryBuilder.VALID_TABLES:
            logger.warning(f"Invalid table name attempted: {table_name}")
            raise SecurityValidationError(
                f"Invalid table name: '{table_name}'. "
                f"Allowed tables: {', '.join(sorted(SecureQueryBuilder.VALID_TABLES))}"
            )
        
        return table_name_lower
    
    @staticmethod
    def _validate_column_names(table_name: str, columns: List[str]) -> List[str]:
        """
        Validate column names against allowlist for specific table.
        
        Args:
            table_name: Table name (already validated)
            columns: List of column names to validate
            
        Returns:
            List of validated column names
            
        Raises:
            SecurityValidationError: If any column name is invalid
        """
        if not columns:
            raise SecurityValidationError("Column list cannot be empty")
        
        valid_columns = SecureQueryBuilder.VALID_COLUMNS.get(table_name, set())
        
        validated = []
        for col in columns:
            col_lower = col.lower().strip()
            
            if col_lower not in valid_columns:
                logger.warning(
                    f"Invalid column attempted: {col} for table {table_name}"
                )
                raise SecurityValidationError(
                    f"Invalid column name: '{col}' for table '{table_name}'. "
                    f"Allowed columns: {', '.join(sorted(valid_columns))}"
                )
            
            validated.append(col_lower)
        
        return validated
    
    @staticmethod
    def _validate_aggregate_function(func_name: str) -> str:
        """
        Validate aggregate function name against allowlist.
        
        Args:
            func_name: Function name to validate
            
        Returns:
            Validated function name in uppercase
            
        Raises:
            SecurityValidationError: If function name is invalid
        """
        func_upper = func_name.upper().strip()
        
        if func_upper not in SecureQueryBuilder.VALID_AGGREGATE_FUNCTIONS:
            logger.warning(f"Invalid aggregate function attempted: {func_name}")
            raise SecurityValidationError(
                f"Invalid aggregate function: '{func_name}'. "
                f"Allowed functions: {', '.join(sorted(SecureQueryBuilder.VALID_AGGREGATE_FUNCTIONS))}"
            )
        
        return func_upper
    
    @staticmethod
    def _validate_sort_direction(direction: str) -> str:
        """
        Validate sort direction against allowlist.
        
        Args:
            direction: Sort direction to validate
            
        Returns:
            Validated direction in uppercase
            
        Raises:
            SecurityValidationError: If direction is invalid
        """
        direction_upper = direction.upper().strip()
        
        if direction_upper not in SecureQueryBuilder.VALID_SORT_DIRECTIONS:
            logger.warning(f"Invalid sort direction attempted: {direction}")
            raise SecurityValidationError(
                f"Invalid sort direction: '{direction}'. "
                f"Allowed directions: {', '.join(sorted(SecureQueryBuilder.VALID_SORT_DIRECTIONS))}"
            )
        
        return direction_upper
    
    @staticmethod
    def _validate_limit(limit: int) -> int:
        """
        Validate and sanitize LIMIT value.
        
        Args:
            limit: Limit value to validate
            
        Returns:
            Validated limit value
            
        Raises:
            SecurityValidationError: If limit is invalid
        """
        if not isinstance(limit, int):
            raise SecurityValidationError(
                f"LIMIT must be an integer, got {type(limit).__name__}"
            )
        
        if limit < 1:
            raise SecurityValidationError("LIMIT must be at least 1")
        
        if limit > 10000:
            logger.warning(f"Large LIMIT value requested: {limit}")
            raise SecurityValidationError(
                "LIMIT cannot exceed 10,000 (use pagination for larger datasets)"
            )
        
        return limit
    
    @contextmanager
    def _get_connection(self):
        """
        Context manager for database connections with proper cleanup.
        
        Yields:
            Database connection from pool
        """
        conn = None
        try:
            conn = self.connection_pool.getconn()
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error: {str(e)}")
            raise DatabaseQueryError(f"Database operation failed: {str(e)}")
        finally:
            if conn:
                self.connection_pool.putconn(conn)
    
    def get_table_records(
        self,
        table_name: str,
        columns: Optional[List[str]] = None,
        sort_field: Optional[str] = None,
        sort_direction: str = "ASC",
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Securely retrieve records from a table.
        
        Args:
            table_name: Target table (must be in allowlist)
            columns: Column names to select (must be in allowlist, None = all columns)
            sort_field: Field to sort by (must be in allowlist)
            sort_direction: Sort direction (ASC or DESC)
            limit: Maximum number of records to return (1-10,000)
            
        Returns:
            List of records as dictionaries
            
        Raises:
            SecurityValidationError: If any input fails validation
            DatabaseQueryError: If database operation fails
        """
        # Log query attempt for audit trail
        logger.info(
            f"Query attempt: table={table_name}, columns={columns}, "
            f"sort={sort_field}, limit={limit}"
        )
        
        # Validate all inputs
        validated_table = self._validate_table_name(table_name)
        validated_limit = self._validate_limit(limit)
        
        # Build column list
        if columns:
            validated_columns = self._validate_column_names(validated_table, columns)
            column_identifiers = [sql.Identifier(col) for col in validated_columns]
            column_clause = sql.SQL(', ').join(column_identifiers)
        else:
            # Select all columns - use * for the specific table
            column_clause = sql.SQL('*')
        
        # Build base query using psycopg2.sql for safe identifier quoting
        query = sql.SQL("SELECT {columns} FROM {table}").format(
            columns=column_clause,
            table=sql.Identifier(validated_table)
        )
        
        # Add ORDER BY clause if specified
        params = []
        if sort_field:
            validated_sort_field = self._validate_column_names(
                validated_table, [sort_field]
            )[0]
            validated_direction = self._validate_sort_direction(sort_direction)
            
            # Note: sql.SQL() for direction is safe since it's validated against allowlist
            query = sql.SQL("{query} ORDER BY {sort_field} {direction}").format(
                query=query,
                sort_field=sql.Identifier(validated_sort_field),
                direction=sql.SQL(validated_direction)
            )
        
        # Add LIMIT clause (parameterized)
        query = sql.SQL("{query} LIMIT %s").format(query=query)
        params.append(validated_limit)
        
        # Execute query
        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, params)
                
                # Fetch column names
                columns_fetched = [desc[0] for desc in cursor.description]
                
                # Fetch and format results
                results = []
                for row in cursor.fetchall():
                    results.append(dict(zip(columns_fetched, row)))
                
                logger.info(f"Query successful: returned {len(results)} records")
                return results
    
    def generate_report(
        self,
        table_name: str,
        group_by_column: Optional[str] = None,
        aggregate_function: str = "COUNT"
    ) -> List[Dict[str, Any]]:
        """
        Securely generate aggregated report from table.
        
        Args:
            table_name: Target table (must be in allowlist)
            group_by_column: Column to group by (must be in allowlist)
            aggregate_function: Aggregate function (must be in allowlist)
            
        Returns:
            Aggregated results as list of dictionaries
            
        Raises:
            SecurityValidationError: If any input fails validation
            DatabaseQueryError: If database operation fails
        """
        # Log query attempt
        logger.info(
            f"Report generation: table={table_name}, "
            f"group_by={group_by_column}, agg={aggregate_function}"
        )
        
        # Validate inputs
        validated_table = self._validate_table_name(table_name)
        validated_function = self._validate_aggregate_function(aggregate_function)
        
        # Build query based on whether grouping is requested
        if group_by_column:
            validated_group_by = self._validate_column_names(
                validated_table, [group_by_column]
            )[0]
            
            query = sql.SQL(
                "SELECT {group_col}, {agg_func}(*) as count "
                "FROM {table} "
                "GROUP BY {group_col}"
            ).format(
                group_col=sql.Identifier(validated_group_by),
                agg_func=sql.SQL(validated_function),
                table=sql.Identifier(validated_table)
            )
        else:
            query = sql.SQL(
                "SELECT {agg_func}(*) as count FROM {table}"
            ).format(
                agg_func=sql.SQL(validated_function),
                table=sql.Identifier(validated_table)
            )
        
        # Execute query
        with self._get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query)
                
                # Fetch column names
                columns_fetched = [desc[0] for desc in cursor.description]
                
                # Fetch and format results
                results = []
                for row in cursor.fetchall():
                    results.append(dict(zip(columns_fetched, row)))
                
                logger.info(f"Report generated: {len(results)} rows")
                return results


# =============================================================================
# Connection Pool Management
# =============================================================================

class DatabaseConnectionPool:
    """
    Manages database connection pool lifecycle.
    """
    
    def __init__(
        self,
        min_connections: int = 1,
        max_connections: int = 20,
        **connection_params
    ):
        """
        Initialize connection pool.
        
        Args:
            min_connections: Minimum pool size
            max_connections: Maximum pool size
            **connection_params: Database connection parameters
        """
        self.pool = pool.SimpleConnectionPool(
            min_connections,
            max_connections,
            **connection_params
        )
        logger.info(
            f"Connection pool created: "
            f"min={min_connections}, max={max_connections}"
        )
    
    def get_query_builder(self) -> SecureQueryBuilder:
        """
        Get a query builder instance using this pool.
        
        Returns:
            SecureQueryBuilder instance
        """
        return SecureQueryBuilder(self.pool)
    
    def close(self):
        """Close all connections in the pool."""
        if self.pool:
            self.pool.closeall()
            logger.info("Connection pool closed")


# =============================================================================
# Usage Example
# =============================================================================

def example_usage():
    """
    Demonstrates secure usage of the refactored code.
    """
    # Database connection parameters
    connection_params = {
        'host': 'localhost',
        'database': 'mydb',
        'user': 'myuser',
        'password': 'mypassword',
        'connect_timeout': 10
    }
    
    # Create connection pool
    db_pool = DatabaseConnectionPool(
        min_connections=2,
        max_connections=10,
        **connection_params
    )
    
    try:
        # Get query builder
        query_builder = db_pool.get_query_builder()
        
        # Example 1: Get user records
        users = query_builder.get_table_records(
            table_name='users',
            columns=['id', 'username', 'email'],
            sort_field='created_at',
            sort_direction='DESC',
            limit=50
        )
        print(f"Retrieved {len(users)} users")
        
        # Example 2: Generate aggregated report
        category_report = query_builder.generate_report(
            table_name='products',
            group_by_column='category',
            aggregate_function='COUNT'
        )
        print(f"Category report: {category_report}")
        
        # Example 3: Handling invalid input (will raise SecurityValidationError)
        try:
            malicious = query_builder.get_table_records(
                table_name='users; DROP TABLE users--',  # Blocked by allowlist
                limit=10
            )
        except SecurityValidationError as e:
            print(f"Security validation blocked attack: {e}")
        
    finally:
        # Clean up
        db_pool.close()


if __name__ == '__main__':
    example_usage()
