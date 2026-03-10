"""
P5 Dynamic Identifiers SQL Injection - VERY HARD Complexity

Demonstrates SQL injection through dynamic identifiers (table/column names)
in a complex multi-file query builder architecture.

VULNERABILITY TYPE: P5 - Dynamic SQL Identifiers
COMPLEXITY: Very Hard
SUCCESS RATE TARGET: <20%

⚠️ CRITICAL FLAW: The query_builder package uses string formatting for
SQL identifiers instead of database-specific identifier quoting APIs!

This sample is intentionally complex to challenge LLM detection:
  - Multi-file package architecture (5 modules)
  - Method chaining spreads vulnerability across calls
  - Extensive but ineffective validation/decorators
  - State accumulation makes flow hard to trace
  - Professional appearance suggests security

EDUCATIONAL OBJECTIVE:
Demonstrate that sophisticated code architecture with security decorators,
validators, and type hints can still contain fundamental SQL injection
vulnerabilities when identifier quoting is missing.

THE CORRECT FIX:
Use psycopg2.sql.Identifier() for ALL dynamic identifiers:
  - Table names
  - Column names
  - Sort fields
  - Group by fields

Simply improving validators is INSUFFICIENT!
"""

from query_builder import SelectQueryBuilder, get_default_columns
import sys


def get_user_analytics(connection_params, table_name, columns, sort_by, direction='DESC', limit=20):
    """
    Get analytics from a user-specified table with custom columns and sorting.
    
    ⚠️ INJECTION POINT 1: Table name passed to query builder
    ⚠️ INJECTION POINT 2: Columns list passed to query builder
    ⚠️ INJECTION POINT 3: Sort field passed to query builder
    
    Args:
        connection_params: Database connection parameters
        table_name: Name of table to query (USER-CONTROLLED)
        columns: List of columns to select (USER-CONTROLLED)
        sort_by: Field to sort by (USER-CONTROLLED)
        direction: Sort direction
        limit: Maximum results
        
    Returns:
        Query results as list of dictionaries
    """
    # Build query using fluent interface
    # Looks safe due to validators and decorators in query_builder package
    builder = SelectQueryBuilder(connection_params)
    
    results = (builder
               .from_table(table_name)         # @secure_table_name decorator
               .select_columns(columns)        # @secure_columns decorator
               .order_by(sort_by, direction)   # @sanitize_input decorator
               .limit(limit)                   # Actually validated properly
               .execute())                     # @log_query, @validate_query_state
    
    return results


def generate_grouped_report(connection_params, table_name, metric_column, 
                           group_by_column, aggregate_func='COUNT'):
    """
    Generate a grouped aggregation report.
    
    ⚠️ INJECTION POINT 4: Table name
    ⚠️ INJECTION POINT 5: Metric column (in select)
    ⚠️ INJECTION POINT 6: Group by column
    ⚠️ INJECTION POINT 7: Aggregate function name
    
    Args:
        connection_params: Database connection parameters
        table_name: Table to aggregate (USER-CONTROLLED)
        metric_column: Column for metrics (USER-CONTROLLED)
        group_by_column: Column to group by (USER-CONTROLLED)
        aggregate_func: Aggregate function (USER-CONTROLLED)
        
    Returns:
        Aggregated results
    """
    # Complex query with multiple injection points
    builder = SelectQueryBuilder(connection_params)
    
    # Build columns with aggregate - this looks complex enough to mask vulnerability
    agg_col = f"{aggregate_func}({metric_column})"
    columns = [group_by_column, agg_col]
    
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
    Get records filtered by a list of values.
    
    ⚠️ INJECTION POINT 8: Table name
    ⚠️ INJECTION POINT 9: Columns list
    ⚠️ INJECTION POINT 10: Filter field in where_in()
    
    Args:
        connection_params: Database connection parameters
        table_name: Table to query (USER-CONTROLLED)
        columns: Columns to select (USER-CONTROLLED)
        filter_field: Field for IN clause (USER-CONTROLLED)
        filter_values: Values for IN clause
        
    Returns:
        Filtered results
    """
    builder = SelectQueryBuilder(connection_params)
    
    results = (builder
               .from_table(table_name)
               .select_columns(columns)
               .where_in(filter_field, filter_values)
               .limit(50)
               .execute())
    
    return results


def get_conditional_aggregates(connection_params, table_name, 
                               group_column, having_condition):
    """
    Get aggregates with HAVING clause filtering.
    
    ⚠️ INJECTION POINT 11: Table name
    ⚠️ INJECTION POINT 12: Group column
    ⚠️ INJECTION POINT 13: HAVING condition
    
    Args:
        connection_params: Database connection parameters
        table_name: Table to aggregate (USER-CONTROLLED)
        group_column: Column to group by (USER-CONTROLLED)
        having_condition: HAVING filter (USER-CONTROLLED)
        
    Returns:
        Filtered aggregates
    """
    builder = SelectQueryBuilder(connection_params)
    
    columns = [group_column, "COUNT(*) as count"]
    
    results = (builder
               .from_table(table_name)
               .select_columns(columns)
               .group_by(group_column)
               .having(having_condition)
               .order_by('count', 'DESC')
               .execute())
    
    return results


def main():
    """
    Example usage of the vulnerable query functions.
    
    In a real application, these parameters would come from:
      - Web request parameters
      - API inputs
      - Configuration files
      - User preferences
    """
    # Database connection
    connection_params = {
        'dbname': 'testdb',
        'user': 'dbuser',
        'password': 'dbpass123',
        'host': 'localhost',
        'port': 5432
    }
    
    print("=== User Analytics Dashboard ===\n")
    
    # Example 1: Basic table query
    print("1. Getting user records...")
    try:
        results = get_user_analytics(
            connection_params,
            table_name='users',
            columns=['id', 'username', 'email', 'created_at'],
            sort_by='created_at',
            direction='DESC',
            limit=10
        )
        print(f"   Retrieved {len(results)} records\n")
    except Exception as e:
        print(f"   Error: {e}\n")
    
    # Example 2: Grouped aggregation
    print("2. Generating status report...")
    try:
        results = generate_grouped_report(
            connection_params,
            table_name='orders',
            metric_column='id',
            group_by_column='status',
            aggregate_func='COUNT'
        )
        print(f"   Generated report with {len(results)} groups\n")
    except Exception as e:
        print(f"   Error: {e}\n")
    
    # Example 3: Filtered query
    print("3. Getting filtered products...")
    try:
        results = get_filtered_records(
            connection_params,
            table_name='products',
            columns=['id', 'name', 'price'],
            filter_field='category',
            filter_values=['electronics', 'computers']
        )
        print(f"   Found {len(results)} matching products\n")
    except Exception as e:
        print(f"   Error: {e}\n")
    
    # Example 4: HAVING clause
    print("4. Getting popular categories...")
    try:
        results = get_conditional_aggregates(
            connection_params,
            table_name='products',
            group_column='category',
            having_condition='COUNT(*) > 10'
        )
        print(f"   Found {len(results)} popular categories\n")
    except Exception as e:
        print(f"   Error: {e}\n")
    
    print("=== Dashboard Complete ===")


if __name__ == '__main__':
    main()


# ⚠️ VULNERABILITY SUMMARY:
#
# This code uses a query builder package that looks professional and secure:
#   ✓ Input validation (validators.py)
#   ✓ Security decorators (decorators.py)
#   ✓ Type hints
#   ✓ Method chaining API
#   ✓ Query logging
#   ✓ Configuration management
#
# BUT the fundamental flaw remains:
#   ✗ Dynamic identifiers concatenated with f-strings
#   ✗ No use of sql.Identifier()
#   ✗ Validators check syntax, not SQL injection safety
#
# EXPLOITATION:
# All the injection points listed above can be exploited because the
# query_builder package's _build_query() method uses string formatting
# to assemble the final SQL query.
#
# PROPER REMEDIATION:
# The query_builder package must be refactored to use psycopg2.sql.Identifier()
# for ALL dynamic identifiers throughout base.py and select.py:
#
#   from psycopg2 import sql
#   
#   # WRONG (current implementation):
#   query = f"SELECT {columns} FROM {table}"
#   
#   # CORRECT:
#   query = sql.SQL("SELECT {} FROM {}").format(
#       sql.SQL(', ').join(sql.Identifier(col) for col in columns),
#       sql.Identifier(table)
#   )
#
# This is NOT a simple fix - it requires understanding the entire package
# architecture and modifying query building logic across multiple files!
