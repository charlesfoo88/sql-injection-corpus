"""
Query Builder Usage Examples (SECURE VERSION)

This file demonstrates secure usage of the query builder with proper
SQL injection protection through identifier escaping and parameterized queries.
"""

from query_builder import SelectQueryBuilder


def get_user_analytics(connection_params, table_name, columns, sort_by, direction='DESC', limit=20):
    """
    Get analytics from user table - now secure against SQL injection.
    
    Args:
        connection_params: Database connection parameters
        table_name: Name of table to query (will be validated and escaped)
        columns: List of column names (will be validated and escaped)
        sort_by: Field to sort by (will be validated and escaped)
        direction: Sort direction (whitelisted to ASC/DESC only)
        limit: Maximum rows to return (validated range 1-1000)
        
    Returns:
        List of result dictionaries
        
    Security:
        All identifiers are validated and escaped to prevent SQL injection.
    """
    builder = SelectQueryBuilder(connection_params)
    
    results = (builder
               .from_table(table_name)  # Properly escaped
               .select_columns(columns)  # Properly escaped
               .order_by(sort_by, direction)  # Properly escaped
               .limit(limit)
               .execute())
    
    return results


def generate_grouped_report(connection_params, table_name, metric_column, 
                           group_by_column, aggregate_func='COUNT'):
    """
    Generate report with grouping and aggregation - secure version.
    
    Args:
        connection_params: Database connection parameters
        table_name: Name of table to query
        metric_column: Column to aggregate
        group_by_column: Column to group by
        aggregate_func: Aggregate function (for future enhancement)
        
    Returns:
        List of grouped results
        
    Note:
        For aggregate functions in SELECT, you would need to extend the builder
        to support them securely. For now, using basic columns.
        
    Security:
        All identifiers are validated and escaped.
    """
    builder = SelectQueryBuilder(connection_params)
    
    # Note: For aggregate functions, you'd need to extend the builder
    # to support them securely. For now, using basic columns.
    columns = [group_by_column, metric_column]
    
    results = (builder
               .from_table(table_name)
               .select_columns(columns)
               .group_by(group_by_column)
               .order_by(group_by_column, 'ASC')
               .execute())
    
    return results


def get_filtered_records(connection_params, table_name, columns, 
                        filter_field, filter_values):
    """
    Get records with IN filter - now using parameterized queries.
    
    Args:
        connection_params: Database connection parameters
        table_name: Name of table to query
        columns: List of columns to select
        filter_field: Field to filter on
        filter_values: List of values for IN clause
        
    Returns:
        List of filtered results
        
    Security:
        - Field name is validated and escaped
        - Values are parameterized (prevents injection)
    """
    builder = SelectQueryBuilder(connection_params)
    
    results = (builder
               .from_table(table_name)
               .select_columns(columns)
               .where_in(filter_field, filter_values)  # Parameterized
               .limit(50)
               .execute())
    
    return results


def get_conditional_aggregates(connection_params, table_name, 
                               group_column, having_field, having_operator, having_value):
    """
    Get aggregates with HAVING condition - secure version with explicit parameters.
    
    Args:
        connection_params: Database connection parameters
        table_name: Name of table to query
        group_column: Column to group by
        having_field: Field for HAVING condition
        having_operator: Comparison operator (whitelisted)
        having_value: Value to compare against (parameterized)
        
    Returns:
        List of filtered aggregate results
        
    Security:
        - All identifiers validated and escaped
        - Operator is whitelisted
        - Value is parameterized
        
    Note:
        Aggregate functions in SELECT require additional secure implementation.
    """
    builder = SelectQueryBuilder(connection_params)
    
    # Note: Aggregate functions in SELECT require additional secure implementation
    columns = [group_column]
    
    results = (builder
               .from_table(table_name)
               .select_columns(columns)
               .group_by(group_column)
               .having(having_field, having_operator, having_value)  # Parameterized
               .order_by(group_column, 'DESC')
               .execute())
    
    return results


def get_users_by_status(connection_params, status_value):
    """
    Example showing WHERE clause with parameterized queries.
    
    Args:
        connection_params: Database connection parameters
        status_value: Status to filter by (will be parameterized)
        
    Returns:
        List of users with matching status
        
    Security:
        The status value is parameterized, preventing SQL injection
        even if status_value contains malicious SQL.
    """
    builder = SelectQueryBuilder(connection_params)
    
    results = (builder
               .from_table('users')
               .select_columns(['id', 'username', 'email', 'status'])
               .where('status', '=', status_value)  # Parameterized - SECURE
               .order_by('created_at', 'DESC')
               .limit(100)
               .execute())
    
    return results


# Database connection configuration
connection_params = {
    'dbname': 'testdb',
    'user': 'dbuser',
    'password': 'dbpass123',
    'host': 'localhost',
    'port': 5432
}

# Example usage
if __name__ == '__main__':
    # Example 1: Basic query with proper escaping
    print("Example 1: Basic user analytics")
    results = get_user_analytics(
        connection_params,
        table_name='users',
        columns=['id', 'username', 'email'],
        sort_by='created_at',
        limit=10
    )
    print(f"Found {len(results)} records")
    
    # Example 2: Query with WHERE clause (parameterized)
    print("\nExample 2: Filter by status")
    active_users = get_users_by_status(connection_params, 'active')
    print(f"Found {len(active_users)} active users")
    
    # Example 3: Query with WHERE IN (parameterized)
    print("\nExample 3: Filter with IN clause")
    filtered = get_filtered_records(
        connection_params,
        table_name='users',
        columns=['id', 'username'],
        filter_field='status',
        filter_values=['active', 'pending', 'approved']
    )
    print(f"Found {len(filtered)} users with specified statuses")
    
    # Example 4: Attempting SQL injection (will fail safely)
    print("\nExample 4: SQL injection attempt (will be prevented)")
    try:
        # This would have been vulnerable in the old version
        # Now it will raise ValueError due to identifier validation
        malicious_results = get_user_analytics(
            connection_params,
            table_name="users; DROP TABLE users--",  # Injection attempt
            columns=['id', 'username'],
            sort_by='id',
            limit=10
        )
    except ValueError as e:
        print(f"SQL injection prevented: {e}")
    
    print("\nAll examples completed successfully!")
