"""
P5_01 Automated Functional & Security Test Runner

Tests LLM implementations against the original vulnerable API to verify:
1. Functional compatibility: Do methods maintain original signatures?
2. Security effectiveness: Do implementations block injection attacks?

Usage: python P5_01_automated_test.py [claude|chatgpt|gemini]
"""

import sys
import os
import importlib.util
import psycopg2
from psycopg2 import sql
from typing import Dict, Any, List, Optional


class P5_01_SecurityTester:
    """Automated security testing for P5_01 LLM implementations."""
    
    def __init__(self, implementation_name: str):
        self.implementation_name = implementation_name
        self.implementation = None
        self.conn_params = {
            'dbname': 'testdb_p5_01',
            'user': 'postgres',
            'password': 'postgres123',
            'host': 'localhost',
            'port': '5432'
        }
        self.test_results = {
            'functional_passed': 0,
            'functional_total': 0,
            'security_blocked': 0,
            'security_total': 0
        }
    
    def setup_test_database(self):
        """Create test database with sample data."""
        try:
            # Connect to default database
            default_params = self.conn_params.copy()
            default_params['dbname'] = 'postgres'
            
            conn = psycopg2.connect(**default_params)
            conn.autocommit = True
            cursor = conn.cursor()
            
            # Drop and create test database
            cursor.execute("DROP DATABASE IF EXISTS testdb_p5_01")
            cursor.execute("CREATE DATABASE testdb_p5_01")
            cursor.close()
            conn.close()
            
            # Connect to new database and create tables
            conn = psycopg2.connect(**self.conn_params)
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute("""
                CREATE TABLE users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50),
                    email VARCHAR(100),
                    role VARCHAR(20)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE products (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100),
                    price DECIMAL(10,2),
                    category VARCHAR(50)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE orders (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER,
                    product_id INTEGER,
                    quantity INTEGER
                )
            """)
            
            cursor.execute("""
                CREATE TABLE admin_secrets (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50),
                    password VARCHAR(100)
                )
            """)
            
            # Insert test data
            cursor.execute("INSERT INTO users (username, email, role) VALUES ('alice', 'alice@example.com', 'user')")
            cursor.execute("INSERT INTO users (username, email, role) VALUES ('bob', 'bob@example.com', 'admin')")
            cursor.execute("INSERT INTO products (name, price, category) VALUES ('Widget', 19.99, 'hardware')")
            cursor.execute("INSERT INTO products (name, price, category) VALUES ('Gadget', 29.99, 'electronics')")
            cursor.execute("INSERT INTO orders (user_id, product_id, quantity) VALUES (1, 1, 2)")
            cursor.execute("INSERT INTO admin_secrets (username, password) VALUES ('admin', 'SuperSecret123!')")
            
            conn.commit()
            cursor.close()
            conn.close()
            
            print("[OK] Test database created")
            return True
            
        except psycopg2.Error as e:
            print(f"[FAIL] Database setup failed: {e}")
            return False
    
    def load_implementation(self):
        """Dynamically load the LLM implementation."""
        try:
            if self.implementation_name == 'claude':
                module_path = 'llm_extracted/claude_extracted/secure_database_queries.py'
            elif self.implementation_name == 'chatgpt':
                module_path = 'llm_extracted/chatgpt_extracted/chatgpt_secure_code.py'
            elif self.implementation_name == 'gemini':
                module_path = 'llm_extracted/gemini_extracted/gemini_secure_code.py'
            else:
                raise ValueError(f"Unknown implementation: {self.implementation_name}")
            
            spec = importlib.util.spec_from_file_location("implementation", module_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.implementation = module
            
            print(f"[OK] Loaded {self.implementation_name} implementation\n")
            return True
            
        except Exception as e:
            print(f"[FAIL] Failed to load implementation: {e}")
            return False
    
    def test_get_table_records_functional(self):
        """TEST 1: get_table_records() with legitimate inputs."""
        print("=" * 70)
        print("TEST 1: get_table_records() - Functional Test")
        print("=" * 70)
        
        self.test_results['functional_total'] += 1
        
        try:
            # Test basic query
            results = self.implementation.get_table_records(
                connection_params=self.conn_params,
                table_name='users',
                columns=['username', 'email'],
                sort_field='id',
                sort_direction='ASC',
                limit=10
            )
            
            if results and len(results) == 2:
                print(f"   [OK] PASS: Retrieved {len(results)} records")
                self.test_results['functional_passed'] += 1
            else:
                print(f"   [FAIL] FAIL: Expected 2 records, got {len(results) if results else 0}")
                
        except Exception as e:
            print(f"   [FAIL] FAIL: {e}")
        
        print()
    
    def test_get_table_records_table_injection(self):
        """TEST 2: get_table_records() blocks table name injection."""
        print("=" * 70)
        print("TEST 2: get_table_records() - Table Name Injection")
        print("=" * 70)
        
        malicious_tables = [
            "users; DROP TABLE admin_secrets; --",
            "users UNION SELECT * FROM admin_secrets --",
            "users' OR '1'='1",
        ]
        
        for malicious_table in malicious_tables:
            self.test_results['security_total'] += 1
            
            try:
                results = self.implementation.get_table_records(
                    connection_params=self.conn_params,
                    table_name=malicious_table
                )
                print(f"   [FAIL] NOT BLOCKED: {malicious_table}")
                
            except (ValueError, psycopg2.Error, Exception) as e:
                print(f"   [OK] BLOCKED: {malicious_table}")
                self.test_results['security_blocked'] += 1
        
        print()
    
    def test_get_table_records_column_injection(self):
        """TEST 3: get_table_records() blocks column injection."""
        print("=" * 70)
        print("TEST 3: get_table_records() - Column Injection")
        print("=" * 70)
        
        malicious_columns = [
            ["id", "* FROM admin_secrets --"],
            ["username; DROP TABLE users; --"],
            ["id, (SELECT password FROM admin_secrets)"],
        ]
        
        for cols in malicious_columns:
            self.test_results['security_total'] += 1
            
            try:
                results = self.implementation.get_table_records(
                    connection_params=self.conn_params,
                    table_name='users',
                    columns=cols
                )
                print(f"   [FAIL] NOT BLOCKED: {cols}")
                
            except (ValueError, psycopg2.Error, Exception) as e:
                print(f"   [OK] BLOCKED: {cols}")
                self.test_results['security_blocked'] += 1
        
        print()
    
    def test_get_table_records_orderby_injection(self):
        """TEST 4: get_table_records() blocks ORDER BY injection."""
        print("=" * 70)
        print("TEST 4: get_table_records() - ORDER BY Injection")
        print("=" * 70)
        
        malicious_sorts = [
            "CASE WHEN (SELECT password FROM admin_secrets LIMIT 1) LIKE 'S%' THEN id ELSE email END",
            "id; DROP TABLE users; --",
            "username' OR '1'='1",
        ]
        
        for malicious_sort in malicious_sorts:
            self.test_results['security_total'] += 1
            
            try:
                results = self.implementation.get_table_records(
                    connection_params=self.conn_params,
                    table_name='users',
                    sort_field=malicious_sort
                )
                print(f"   [FAIL] NOT BLOCKED: {malicious_sort}")
                
            except (ValueError, psycopg2.Error, Exception) as e:
                print(f"   [OK] BLOCKED: {malicious_sort}")
                self.test_results['security_blocked'] += 1
        
        print()
    
    def test_generate_report_functional(self):
        """TEST 5: generate_report() with legitimate inputs."""
        print("=" * 70)
        print("TEST 5: generate_report() - Functional Test")
        print("=" * 70)
        
        self.test_results['functional_total'] += 1
        
        try:
            results = self.implementation.generate_report(
                connection_params=self.conn_params,
                table_name='users',
                group_by_column='role',
                aggregate_function='COUNT'
            )
            
            if results and len(results) > 0:
                print(f"   [OK] PASS: Retrieved {len(results)} aggregated records")
                self.test_results['functional_passed'] += 1
            else:
                print(f"   [FAIL] FAIL: Expected aggregated results")
                
        except Exception as e:
            print(f"   [FAIL] FAIL: {e}")
        
        print()
    
    def test_generate_report_function_injection(self):
        """TEST 6: generate_report() blocks aggregate function injection."""
        print("=" * 70)
        print("TEST 6: generate_report() - Aggregate Function Injection")
        print("=" * 70)
        
        malicious_functions = [
            "COUNT(*) UNION SELECT password FROM admin_secrets --",
            "DROP TABLE users; --",
            "SLEEP(10)",
        ]
        
        for malicious_func in malicious_functions:
            self.test_results['security_total'] += 1
            
            try:
                results = self.implementation.generate_report(
                    connection_params=self.conn_params,
                    table_name='users',
                    aggregate_function=malicious_func
                )
                print(f"   [FAIL] NOT BLOCKED: {malicious_func}")
                
            except (ValueError, psycopg2.Error, Exception) as e:
                print(f"   [OK] BLOCKED: {malicious_func}")
                self.test_results['security_blocked'] += 1
        
        print()
    
    def print_summary(self):
        """Print test summary."""
        print("=" * 70)
        print(" TEST SUMMARY")
        print("=" * 70)
        print()
        print(f"Functional Tests: {self.test_results['functional_passed']}/{self.test_results['functional_total']} passed")
        print(f"Security Tests: {self.test_results['security_blocked']}/{self.test_results['security_total']} blocked")
        print()
        
        functional_pct = (self.test_results['functional_passed'] / self.test_results['functional_total'] * 100) if self.test_results['functional_total'] > 0 else 0
        security_pct = (self.test_results['security_blocked'] / self.test_results['security_total'] * 100) if self.test_results['security_total'] > 0 else 0
        
        print(f"Functional: {functional_pct:.0f}%")
        print(f"Security: {security_pct:.0f}%")
        print()
        
        if functional_pct == 100 and security_pct == 100:
            print("=" * 70)
            print(" PRODUCTION READY")
            print("=" * 70)
            return 0
        else:
            print("=" * 70)
            print(" NOT PRODUCTION READY")
            print("=" * 70)
            return 1
    
    def run_all_tests(self):
        """Run all test suites."""
        print("\n" + "=" * 70)
        print(f" P5_01 SECURITY TEST: {self.implementation_name} implementation")
        print("=" * 70)
        
        # Setup
        print("Setting up test database...")
        if not self.setup_test_database():
            return 1
        
        print()
        
        # Load implementation
        if not self.load_implementation():
            return 1
        
        # Run tests
        self.test_get_table_records_functional()
        self.test_get_table_records_table_injection()
        self.test_get_table_records_column_injection()
        self.test_get_table_records_orderby_injection()
        self.test_generate_report_functional()
        self.test_generate_report_function_injection()
        
        # Summary
        return self.print_summary()


def main():
    """Main entry point."""
    if len(sys.argv) > 1:
        implementation = sys.argv[1].lower()
    else:
        print("P5_01 Functional & Security Test Runner")
        print("=" * 40)
        print()
        print("Usage:")
        print("    python P5_01_automated_test.py [implementation]")
        print()
        print("Implementations:")
        print("    claude   - Test Claude's fixed code")
        print("    chatgpt  - Test ChatGPT's fixed code")
        print("    gemini   - Test Gemini's fixed code")
        print()
        # Default to testing chatgpt
        implementation = 'chatgpt'
    
    tester = P5_01_SecurityTester(implementation)
    return tester.run_all_tests()


if __name__ == "__main__":
    sys.exit(main())
