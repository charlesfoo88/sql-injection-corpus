"""
Unit Tests for Secure Database Query Module

Tests cover:
1. SQL injection attempt detection and blocking
2. Input validation (allowlist enforcement)
3. Proper query construction
4. Error handling
5. Connection pool management

Author: Security Review Team
Date: February 10, 2026
"""

import pytest
from unittest.mock import Mock, MagicMock, patch, call
from psycopg2 import sql
import psycopg2.pool

# Import the module to test
from secure_database_queries import (
    SecureQueryBuilder,
    DatabaseConnectionPool,
    SecurityValidationError,
    DatabaseQueryError
)


class TestSecureQueryBuilder:
    """Test suite for SecureQueryBuilder class."""
    
    @pytest.fixture
    def mock_pool(self):
        """Create a mock connection pool."""
        pool = Mock(spec=psycopg2.pool.SimpleConnectionPool)
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        
        # Setup cursor mock
        mock_cursor.description = [('id',), ('name',)]
        mock_cursor.fetchall.return_value = [
            (1, 'Test User'),
            (2, 'Another User')
        ]
        
        # Setup connection mock
        mock_conn.cursor.return_value.__enter__ = Mock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = Mock(return_value=False)
        
        # Setup pool mock
        pool.getconn.return_value = mock_conn
        
        return pool
    
    @pytest.fixture
    def query_builder(self, mock_pool):
        """Create a SecureQueryBuilder instance with mock pool."""
        return SecureQueryBuilder(mock_pool)
    
    # =========================================================================
    # SQL Injection Attack Tests
    # =========================================================================
    
    def test_sql_injection_table_name_union_attack(self, query_builder):
        """Test that UNION-based SQL injection in table name is blocked."""
        with pytest.raises(SecurityValidationError) as exc_info:
            query_builder.get_table_records(
                table_name="users UNION SELECT * FROM passwords--",
                limit=10
            )
        
        assert "Invalid table name" in str(exc_info.value)
        assert "users UNION SELECT" in str(exc_info.value)
    
    def test_sql_injection_table_name_drop_table(self, query_builder):
        """Test that DROP TABLE attack in table name is blocked."""
        with pytest.raises(SecurityValidationError) as exc_info:
            query_builder.get_table_records(
                table_name="users; DROP TABLE users--",
                limit=10
            )
        
        assert "Invalid table name" in str(exc_info.value)
    
    def test_sql_injection_table_name_comment_injection(self, query_builder):
        """Test that comment-based injection in table name is blocked."""
        attacks = [
            "users--",
            "users/*comment*/",
            "users;--"
        ]
        
        for attack in attacks:
            with pytest.raises(SecurityValidationError):
                query_builder.get_table_records(table_name=attack, limit=10)
    
    def test_sql_injection_column_subquery_attack(self, query_builder):
        """Test that subquery injection in column names is blocked."""
        with pytest.raises(SecurityValidationError) as exc_info:
            query_builder.get_table_records(
                table_name="users",
                columns=["id", "(SELECT password FROM admin_users) as stolen"],
                limit=10
            )
        
        assert "Invalid column name" in str(exc_info.value)
    
    def test_sql_injection_column_union_attack(self, query_builder):
        """Test that UNION attack in column names is blocked."""
        with pytest.raises(SecurityValidationError):
            query_builder.get_table_records(
                table_name="users",
                columns=["* FROM users UNION SELECT * FROM passwords--"],
                limit=10
            )
    
    def test_sql_injection_order_by_attack(self, query_builder):
        """Test that SQL injection in ORDER BY clause is blocked."""
        with pytest.raises(SecurityValidationError):
            query_builder.get_table_records(
                table_name="users",
                sort_field="id; DROP TABLE users--",
                limit=10
            )
    
    def test_sql_injection_order_by_blind_attack(self, query_builder):
        """Test that blind SQL injection via ORDER BY is blocked."""
        with pytest.raises(SecurityValidationError):
            query_builder.get_table_records(
                table_name="users",
                sort_field="(CASE WHEN (1=1) THEN id ELSE name END)",
                limit=10
            )
    
    def test_sql_injection_aggregate_function_attack(self, query_builder):
        """Test that SQL injection in aggregate function is blocked."""
        with pytest.raises(SecurityValidationError):
            query_builder.generate_report(
                table_name="products",
                aggregate_function="COUNT(*); DROP TABLE products--"
            )
    
    def test_sql_injection_aggregate_function_subquery(self, query_builder):
        """Test that subquery via aggregate function is blocked."""
        with pytest.raises(SecurityValidationError):
            query_builder.generate_report(
                table_name="products",
                aggregate_function="(SELECT password FROM admin_users)"
            )
    
    def test_sql_injection_group_by_attack(self, query_builder):
        """Test that SQL injection in GROUP BY column is blocked."""
        with pytest.raises(SecurityValidationError):
            query_builder.generate_report(
                table_name="products",
                group_by_column="category; DROP TABLE products--",
                aggregate_function="COUNT"
            )
    
    # =========================================================================
    # Input Validation Tests
    # =========================================================================
    
    def test_invalid_table_name_not_in_allowlist(self, query_builder):
        """Test that table names not in allowlist are rejected."""
        with pytest.raises(SecurityValidationError) as exc_info:
            query_builder.get_table_records(table_name="admin_secrets", limit=10)
        
        assert "Invalid table name" in str(exc_info.value)
        assert "admin_secrets" in str(exc_info.value)
    
    def test_invalid_column_name_not_in_allowlist(self, query_builder):
        """Test that column names not in allowlist are rejected."""
        with pytest.raises(SecurityValidationError) as exc_info:
            query_builder.get_table_records(
                table_name="users",
                columns=["id", "password_hash"],  # password_hash not in allowlist
                limit=10
            )
        
        assert "Invalid column name" in str(exc_info.value)
        assert "password_hash" in str(exc_info.value)
    
    def test_invalid_aggregate_function(self, query_builder):
        """Test that invalid aggregate functions are rejected."""
        with pytest.raises(SecurityValidationError) as exc_info:
            query_builder.generate_report(
                table_name="products",
                aggregate_function="STDDEV"  # Not in allowlist
            )
        
        assert "Invalid aggregate function" in str(exc_info.value)
    
    def test_invalid_sort_direction(self, query_builder):
        """Test that invalid sort directions are rejected."""
        with pytest.raises(SecurityValidationError):
            query_builder.get_table_records(
                table_name="users",
                sort_field="id",
                sort_direction="RANDOM",  # Invalid direction
                limit=10
            )
    
    def test_invalid_limit_negative(self, query_builder):
        """Test that negative LIMIT values are rejected."""
        with pytest.raises(SecurityValidationError):
            query_builder.get_table_records(table_name="users", limit=-1)
    
    def test_invalid_limit_zero(self, query_builder):
        """Test that zero LIMIT value is rejected."""
        with pytest.raises(SecurityValidationError):
            query_builder.get_table_records(table_name="users", limit=0)
    
    def test_invalid_limit_too_large(self, query_builder):
        """Test that excessively large LIMIT values are rejected."""
        with pytest.raises(SecurityValidationError):
            query_builder.get_table_records(table_name="users", limit=100000)
    
    def test_invalid_limit_wrong_type(self, query_builder):
        """Test that non-integer LIMIT values are rejected."""
        with pytest.raises(SecurityValidationError):
            query_builder.get_table_records(table_name="users", limit="100")
    
    def test_empty_table_name(self, query_builder):
        """Test that empty table name is rejected."""
        with pytest.raises(SecurityValidationError):
            query_builder.get_table_records(table_name="", limit=10)
    
    def test_empty_column_list(self, query_builder):
        """Test that empty column list is rejected."""
        with pytest.raises(SecurityValidationError):
            query_builder.get_table_records(
                table_name="users",
                columns=[],
                limit=10
            )
    
    # =========================================================================
    # Valid Query Tests
    # =========================================================================
    
    def test_valid_simple_query(self, query_builder, mock_pool):
        """Test that valid simple queries work correctly."""
        results = query_builder.get_table_records(table_name="users", limit=10)
        
        assert len(results) == 2
        assert results[0]['id'] == 1
        assert results[0]['name'] == 'Test User'
        
        # Verify query was executed
        mock_conn = mock_pool.getconn.return_value
        mock_cursor = mock_conn.cursor.return_value.__enter__.return_value
        assert mock_cursor.execute.called
    
    def test_valid_query_with_columns(self, query_builder, mock_pool):
        """Test valid query with specific columns."""
        results = query_builder.get_table_records(
            table_name="users",
            columns=["id", "username"],
            limit=10
        )
        
        assert len(results) == 2
        mock_cursor = mock_pool.getconn.return_value.cursor.return_value.__enter__.return_value
        assert mock_cursor.execute.called
    
    def test_valid_query_with_sorting(self, query_builder, mock_pool):
        """Test valid query with ORDER BY clause."""
        results = query_builder.get_table_records(
            table_name="users",
            sort_field="id",
            sort_direction="DESC",
            limit=10
        )
        
        assert len(results) == 2
        mock_cursor = mock_pool.getconn.return_value.cursor.return_value.__enter__.return_value
        
        # Verify query contains ORDER BY
        executed_query = mock_cursor.execute.call_args[0][0]
        assert "ORDER BY" in str(executed_query)
    
    def test_valid_aggregate_report_with_grouping(self, query_builder, mock_pool):
        """Test valid aggregation with GROUP BY."""
        # Setup mock for aggregate query
        mock_cursor = mock_pool.getconn.return_value.cursor.return_value.__enter__.return_value
        mock_cursor.description = [('category',), ('count',)]
        mock_cursor.fetchall.return_value = [('electronics', 50), ('books', 30)]
        
        results = query_builder.generate_report(
            table_name="products",
            group_by_column="category",
            aggregate_function="COUNT"
        )
        
        assert len(results) == 2
        assert results[0]['category'] == 'electronics'
        assert results[0]['count'] == 50
    
    def test_valid_aggregate_report_without_grouping(self, query_builder, mock_pool):
        """Test valid aggregation without GROUP BY."""
        mock_cursor = mock_pool.getconn.return_value.cursor.return_value.__enter__.return_value
        mock_cursor.description = [('count',)]
        mock_cursor.fetchall.return_value = [(100,)]
        
        results = query_builder.generate_report(
            table_name="products",
            aggregate_function="COUNT"
        )
        
        assert len(results) == 1
        assert results[0]['count'] == 100
    
    def test_case_insensitive_validation(self, query_builder):
        """Test that validation is case-insensitive."""
        # These should all work
        results = query_builder.get_table_records(table_name="USERS", limit=10)
        assert len(results) == 2
        
        results = query_builder.get_table_records(table_name="Users", limit=10)
        assert len(results) == 2
    
    # =========================================================================
    # Connection Pool Tests
    # =========================================================================
    
    def test_connection_acquired_and_released(self, query_builder, mock_pool):
        """Test that connections are properly acquired and released."""
        query_builder.get_table_records(table_name="users", limit=10)
        
        assert mock_pool.getconn.called
        assert mock_pool.putconn.called
    
    def test_connection_released_on_error(self, query_builder, mock_pool):
        """Test that connections are released even when errors occur."""
        # Cause an error during query execution
        mock_cursor = mock_pool.getconn.return_value.cursor.return_value.__enter__.return_value
        mock_cursor.execute.side_effect = Exception("Database error")
        
        with pytest.raises(DatabaseQueryError):
            query_builder.get_table_records(table_name="users", limit=10)
        
        # Connection should still be released
        assert mock_pool.putconn.called
    
    # =========================================================================
    # Edge Case Tests
    # =========================================================================
    
    def test_whitespace_handling_in_table_name(self, query_builder):
        """Test that whitespace in table names is handled correctly."""
        # Leading/trailing whitespace should be stripped
        results = query_builder.get_table_records(table_name="  users  ", limit=10)
        assert len(results) == 2
    
    def test_all_columns_selection(self, query_builder, mock_pool):
        """Test that None columns parameter selects all columns."""
        results = query_builder.get_table_records(
            table_name="users",
            columns=None,  # Should select *
            limit=10
        )
        
        assert len(results) == 2
        mock_cursor = mock_pool.getconn.return_value.cursor.return_value.__enter__.return_value
        executed_query = str(mock_cursor.execute.call_args[0][0])
        assert "*" in executed_query or "SELECT" in executed_query


class TestDatabaseConnectionPool:
    """Test suite for DatabaseConnectionPool class."""
    
    @patch('secure_database_queries.pool.SimpleConnectionPool')
    def test_pool_initialization(self, mock_pool_class):
        """Test connection pool initialization."""
        connection_params = {
            'host': 'localhost',
            'database': 'testdb',
            'user': 'testuser',
            'password': 'testpass'
        }
        
        db_pool = DatabaseConnectionPool(
            min_connections=2,
            max_connections=10,
            **connection_params
        )
        
        # Verify pool was created with correct parameters
        mock_pool_class.assert_called_once_with(
            2, 10, **connection_params
        )
    
    @patch('secure_database_queries.pool.SimpleConnectionPool')
    def test_pool_cleanup(self, mock_pool_class):
        """Test that pool cleanup closes all connections."""
        db_pool = DatabaseConnectionPool(
            min_connections=1,
            max_connections=5,
            host='localhost'
        )
        
        db_pool.close()
        
        # Verify closeall was called
        mock_pool_class.return_value.closeall.assert_called_once()


# =============================================================================
# Penetration Test Cases
# =============================================================================

class TestPenetrationTests:
    """
    Penetration test cases simulating real attack scenarios.
    """
    
    @pytest.fixture
    def query_builder(self):
        """Create query builder with mock pool."""
        mock_pool = Mock(spec=psycopg2.pool.SimpleConnectionPool)
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        
        mock_cursor.description = [('id',), ('data',)]
        mock_cursor.fetchall.return_value = [(1, 'test')]
        
        mock_conn.cursor.return_value.__enter__ = Mock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = Mock(return_value=False)
        mock_pool.getconn.return_value = mock_conn
        
        return SecureQueryBuilder(mock_pool)
    
    def test_pentest_scenario_1_data_exfiltration(self, query_builder):
        """
        Pentest Scenario 1: Attacker attempts data exfiltration via UNION.
        
        Attack: users UNION SELECT credit_card, ssn FROM sensitive_data--
        Expected: Blocked by allowlist validation
        """
        with pytest.raises(SecurityValidationError):
            query_builder.get_table_records(
                table_name="users UNION SELECT credit_card, ssn FROM sensitive_data--",
                limit=1000
            )
    
    def test_pentest_scenario_2_database_destruction(self, query_builder):
        """
        Pentest Scenario 2: Attacker attempts to drop database.
        
        Attack: products; DROP DATABASE production--
        Expected: Blocked by allowlist validation
        """
        with pytest.raises(SecurityValidationError):
            query_builder.generate_report(
                table_name="products; DROP DATABASE production--",
                aggregate_function="COUNT"
            )
    
    def test_pentest_scenario_3_privilege_escalation(self, query_builder):
        """
        Pentest Scenario 3: Privilege escalation via column injection.
        
        Attack: (UPDATE users SET role='admin' WHERE username='attacker')
        Expected: Blocked by allowlist validation
        """
        with pytest.raises(SecurityValidationError):
            query_builder.get_table_records(
                table_name="users",
                columns=["id", "(UPDATE users SET role='admin' WHERE username='attacker') as x"],
                limit=1
            )
    
    def test_pentest_scenario_4_blind_sql_injection(self, query_builder):
        """
        Pentest Scenario 4: Time-based blind SQL injection.
        
        Attack: id; SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE 1 END--
        Expected: Blocked by allowlist validation
        """
        with pytest.raises(SecurityValidationError):
            query_builder.get_table_records(
                table_name="users",
                sort_field="id; SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE 1 END--",
                limit=1
            )
    
    def test_pentest_scenario_5_stacked_queries(self, query_builder):
        """
        Pentest Scenario 5: Stacked query injection.
        
        Attack: users; INSERT INTO admin_users VALUES ('hacker', 'password')--
        Expected: Blocked by allowlist validation
        """
        with pytest.raises(SecurityValidationError):
            query_builder.get_table_records(
                table_name="users; INSERT INTO admin_users VALUES ('hacker', 'password')--",
                limit=10
            )


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
