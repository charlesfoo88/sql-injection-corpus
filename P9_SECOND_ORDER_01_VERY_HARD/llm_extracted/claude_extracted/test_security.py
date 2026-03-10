"""
Security Test Suite for SQL Injection Remediation

Tests all attack vectors from SQLI-2026-003 to verify fixes.
Run this test suite to validate security improvements.

Requirements:
- pytest
- psycopg2
- PostgreSQL test database
"""

import pytest
import psycopg2
from psycopg2.extras import RealDictCursor
from services.preference_service_secure import PreferenceService
from services.report_service_secure import ReportService
from models.user_preference import UserPreference
from models.report_config import ReportConfig


class TestSQLInjectionPrevention:
    """Test suite for SQL injection prevention."""
    
    @pytest.fixture
    def db_connection(self):
        """Create test database connection."""
        conn = psycopg2.connect(
            dbname="test_security_db",
            user="test_user",
            password="test_pass",
            host="localhost"
        )
        yield conn
        conn.rollback()
        conn.close()
    
    @pytest.fixture
    def preference_service(self, db_connection):
        """Create PreferenceService instance."""
        return PreferenceService(db_connection)
    
    @pytest.fixture
    def report_service(self, db_connection):
        """Create ReportService instance."""
        return ReportService(db_connection)
    
    @pytest.fixture
    def setup_test_data(self, db_connection):
        """Insert test employee data."""
        with db_connection.cursor() as cursor:
            cursor.execute("""
                INSERT INTO employees (username, email, department, role, salary, status)
                VALUES 
                    ('alice', 'alice@example.com', 'IT', 'Developer', 80000, 'active'),
                    ('bob', 'bob@example.com', 'IT', 'Manager', 100000, 'active'),
                    ('charlie', 'charlie@example.com', 'HR', 'Recruiter', 60000, 'active'),
                    ('david', 'david@example.com', 'Finance', 'Analyst', 70000, 'active');
            """)
        db_connection.commit()
    
    # ===================================================================
    # TEST GROUP 1: Input Validation (Preference Service)
    # ===================================================================
    
    def test_save_sort_preference_with_sql_injection_attack(self, preference_service):
        """Test that SQL injection in sort field is rejected at input time."""
        # Attack vector: DROP TABLE command
        result = preference_service.save_sort_preference(
            user_id=1,
            sort_field="id; DROP TABLE employees; --",
            direction="ASC"
        )
        
        assert result['success'] is False
        assert 'error' in result
        assert 'not in allowlist' in result['error']
    
    def test_save_sort_preference_with_union_attack(self, preference_service):
        """Test that UNION-based attack is rejected."""
        result = preference_service.save_sort_preference(
            user_id=1,
            sort_field="id UNION SELECT password FROM admin_users",
            direction="ASC"
        )
        
        assert result['success'] is False
        assert 'error' in result
    
    def test_save_filter_preference_with_or_injection(self, preference_service):
        """Test that OR-based injection in field name is rejected."""
        result = preference_service.save_filter_preference(
            user_id=1,
            filter_field="department' OR '1'='1",
            filter_value="IT"
        )
        
        assert result['success'] is False
        assert 'error' in result
    
    def test_save_groupby_with_malicious_aggregate(self, preference_service):
        """Test that malicious aggregate function is rejected."""
        result = preference_service.save_groupby_preference(
            user_id=1,
            group_field="department",
            aggregate="COUNT(*); DROP TABLE employees; --"
        )
        
        assert result['success'] is False
        assert 'error' in result
    
    # ===================================================================
    # TEST GROUP 2: Execution-Time Validation
    # ===================================================================
    
    def test_database_compromise_simulation(
        self, 
        db_connection, 
        preference_service, 
        report_service
    ):
        """
        Simulate database compromise by directly inserting malicious preference.
        Verify execution-time validation prevents SQL injection.
        """
        # Save a normal preference first
        preference_service.save_sort_preference(
            user_id=999,
            sort_field="username",
            direction="ASC"
        )
        
        # Simulate database compromise: attacker modifies preference directly
        with db_connection.cursor() as cursor:
            cursor.execute("""
                UPDATE user_preferences 
                SET value = %s
                WHERE user_id = %s AND key = %s
            """, (
                "id; DELETE FROM employees WHERE 1=1; --|ASC",
                999,
                'default_sort'
            ))
        db_connection.commit()
        
        # Try to retrieve compromised preference
        retrieved = preference_service.get_sort_preference(user_id=999)
        
        # Should return None due to execution-time validation failure
        assert retrieved is None
        
        # Generate report should use safe defaults
        results = report_service.generate_user_report(user_id=999)
        
        # Verify employees table still exists (not dropped)
        with db_connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM employees")
            count = cursor.fetchone()[0]
        
        assert count >= 0  # Table exists and queryable
    
    def test_malicious_filter_value_parameterized(
        self,
        preference_service,
        report_service,
        setup_test_data
    ):
        """
        Test that malicious filter values are safely parameterized.
        """
        # Save preference with normal field, malicious value
        preference_service.save_filter_preference(
            user_id=2,
            filter_field="department",
            filter_value="IT' OR '1'='1"  # SQL injection attempt
        )
        
        # Generate report
        results = report_service.generate_filtered_report(user_id=2)
        
        # Should return 0 results (no department literally named "IT' OR '1'='1")
        # NOT all employees (which would indicate successful injection)
        assert len(results) == 0
    
    def test_complex_union_attack_in_config(
        self,
        db_connection,
        report_service,
        setup_test_data
    ):
        """
        Test that UNION-based attacks in report configs are blocked.
        """
        # Create config with malicious values directly in database
        config_model = ReportConfig(db_connection)
        
        # Insert malicious config
        with db_connection.cursor() as cursor:
            cursor.execute("""
                INSERT INTO report_configs 
                (user_id, report_name, sort_field, group_by_field, aggregate_function)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            """, (
                3,
                "Malicious Report",
                "id UNION SELECT password, token, 0, '', '', 0 FROM admin_users",
                "department",
                "COUNT(*); INSERT INTO admin_users (username, password) VALUES ('hacker', 'pwned'); --"
            ))
            config_id = cursor.fetchone()[0]
        db_connection.commit()
        
        # Try to generate report from malicious config
        results = report_service.generate_from_config(config_id)
        
        # Should return safe results (malicious fields replaced with defaults)
        assert isinstance(results, list)
        
        # Verify no admin user was created
        with db_connection.cursor() as cursor:
            # This will fail if admin_users table doesn't exist, which is fine
            try:
                cursor.execute(
                    "SELECT COUNT(*) FROM admin_users WHERE username = %s",
                    ('hacker',)
                )
                count = cursor.fetchone()[0]
                assert count == 0
            except psycopg2.errors.UndefinedTable:
                # Table doesn't exist, which means injection didn't work
                pass
    
    # ===================================================================
    # TEST GROUP 3: Parameterized Query Verification
    # ===================================================================
    
    def test_filter_value_special_characters_safe(
        self,
        preference_service,
        report_service,
        setup_test_data
    ):
        """
        Test that special characters in filter values are safely handled.
        """
        special_values = [
            "'; DROP TABLE employees; --",
            "' OR 1=1; --",
            "IT' UNION SELECT password FROM users; --",
            "IT'; DELETE FROM employees WHERE '1'='1",
            "'; UPDATE employees SET salary=999999 WHERE username='alice'; --"
        ]
        
        for malicious_value in special_values:
            preference_service.save_filter_preference(
                user_id=4,
                filter_field="department",
                filter_value=malicious_value
            )
            
            # Generate report
            results = report_service.generate_filtered_report(user_id=4)
            
            # Should return 0 results (treated as literal string)
            assert len(results) == 0
            
            # Verify employees table still exists
            with report_service.conn.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM employees")
                count = cursor.fetchone()[0]
                assert count > 0  # Table not dropped
    
    def test_allowlist_enforcement_comprehensive(self, preference_service):
        """
        Test that only allowlisted field names are accepted.
        """
        # Valid field names
        valid_fields = ['id', 'username', 'email', 'department', 'role']
        for field in valid_fields:
            result = preference_service.save_sort_preference(
                user_id=5,
                sort_field=field,
                direction="ASC"
            )
            assert result['success'] is True
        
        # Invalid field names
        invalid_fields = [
            'password',  # Not in allowlist
            'admin_password',
            'secret_token',
            'id; DROP TABLE users',
            'id--',
            'id/*',
            'id OR 1=1'
        ]
        
        for field in invalid_fields:
            result = preference_service.save_sort_preference(
                user_id=5,
                sort_field=field,
                direction="ASC"
            )
            assert result['success'] is False
    
    # ===================================================================
    # TEST GROUP 4: Edge Cases and Error Handling
    # ===================================================================
    
    def test_null_and_empty_values(self, preference_service):
        """Test handling of null and empty values."""
        # Empty field name
        result = preference_service.save_sort_preference(
            user_id=6,
            sort_field="",
            direction="ASC"
        )
        assert result['success'] is False
        
        # None field name
        result = preference_service.save_sort_preference(
            user_id=6,
            sort_field=None,
            direction="ASC"
        )
        assert result['success'] is False
    
    def test_case_sensitivity_handling(self, preference_service):
        """Test that direction and aggregate are case-insensitive."""
        # Lowercase direction should work
        result = preference_service.save_sort_preference(
            user_id=7,
            sort_field="username",
            direction="asc"
        )
        assert result['success'] is True
        assert result['direction'] == "ASC"  # Normalized to uppercase
        
        # Mixed case aggregate should work
        result = preference_service.save_groupby_preference(
            user_id=7,
            group_field="department",
            aggregate="CoUnT"
        )
        assert result['success'] is True
        assert result['aggregate'] == "COUNT"
    
    def test_default_fallback_on_invalid_preference(
        self,
        report_service,
        setup_test_data
    ):
        """
        Test that reports use safe defaults when preferences are invalid.
        """
        # User with no preferences
        results = report_service.generate_user_report(user_id=999)
        
        # Should return results with default sort (id ASC)
        assert len(results) > 0
        assert results[0]['id'] < results[-1]['id']  # Ascending order
    
    # ===================================================================
    # TEST GROUP 5: Performance and Regression
    # ===================================================================
    
    def test_performance_with_valid_preferences(
        self,
        preference_service,
        report_service,
        setup_test_data
    ):
        """
        Test that valid preferences still work correctly (regression test).
        """
        import time
        
        # Save valid preferences
        preference_service.save_sort_preference(
            user_id=8,
            sort_field="salary",
            direction="DESC"
        )
        
        preference_service.save_filter_preference(
            user_id=8,
            filter_field="department",
            filter_value="IT"
        )
        
        # Time the report generation
        start = time.time()
        results = report_service.generate_user_report(user_id=8)
        end = time.time()
        
        # Should complete quickly (< 100ms)
        assert (end - start) < 0.1
        
        # Should return results sorted by salary DESC
        assert len(results) > 0
        if len(results) > 1:
            assert results[0]['salary'] >= results[1]['salary']
    
    def test_all_report_types_functional(
        self,
        preference_service,
        report_service,
        setup_test_data
    ):
        """
        Regression test: verify all report types still work correctly.
        """
        user_id = 9
        
        # Set up valid preferences
        preference_service.save_sort_preference(
            user_id=user_id,
            sort_field="username",
            direction="ASC"
        )
        
        preference_service.save_filter_preference(
            user_id=user_id,
            filter_field="department",
            filter_value="IT"
        )
        
        preference_service.save_groupby_preference(
            user_id=user_id,
            group_field="department",
            aggregate="COUNT"
        )
        
        # Test all report types
        report1 = report_service.generate_user_report(user_id)
        assert len(report1) > 0
        
        report2 = report_service.generate_filtered_report(user_id)
        assert isinstance(report2, list)
        
        report3 = report_service.generate_grouped_report(user_id)
        assert len(report3) > 0


# ===================================================================
# HELPER: Manual Penetration Testing
# ===================================================================

def manual_penetration_test():
    """
    Manual test to verify SQL injection is blocked.
    Run this separately to verify security.
    """
    import psycopg2
    
    # Connect to test database
    conn = psycopg2.connect(
        dbname="test_security_db",
        user="test_user",
        password="test_pass",
        host="localhost"
    )
    
    pref_service = PreferenceService(conn)
    report_service = ReportService(conn)
    
    print("=== SQL Injection Penetration Test ===\n")
    
    # Test 1: Direct SQL injection in sort field
    print("Test 1: SQL injection in sort field")
    result = pref_service.save_sort_preference(
        user_id=100,
        sort_field="id; DROP TABLE employees; --",
        direction="ASC"
    )
    print(f"Result: {result}")
    assert result['success'] is False
    print("✓ Attack blocked at input layer\n")
    
    # Test 2: Bypass attempt via database manipulation
    print("Test 2: Database compromise simulation")
    pref_service.save_sort_preference(
        user_id=101,
        sort_field="username",
        direction="ASC"
    )
    
    with conn.cursor() as cursor:
        cursor.execute("""
            UPDATE user_preferences 
            SET value = %s
            WHERE user_id = %s AND key = %s
        """, (
            "salary; DELETE FROM employees; --|DESC",
            101,
            'default_sort'
        ))
    conn.commit()
    
    retrieved = pref_service.get_sort_preference(user_id=101)
    print(f"Retrieved preference: {retrieved}")
    assert retrieved is None
    print("✓ Attack blocked at execution layer\n")
    
    # Test 3: Verify table still exists
    print("Test 3: Verify database integrity")
    with conn.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM employees")
        count = cursor.fetchone()[0]
    print(f"Employee count: {count}")
    print("✓ Table not dropped, SQL injection blocked\n")
    
    print("=== All Penetration Tests Passed ===")
    
    conn.close()


if __name__ == "__main__":
    # Run manual penetration test
    manual_penetration_test()
