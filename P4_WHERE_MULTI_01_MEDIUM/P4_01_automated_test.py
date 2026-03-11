"""
P4_01 Automated Functional & Security Test Runner

Tests LLM implementations against the original vulnerable API to verify:
1. Functional compatibility: Do functions maintain original behavior?
2. Security effectiveness: Do implementations block injection attacks?

Usage: 
    python P4_01_automated_test.py --llm [claude|chatgpt|gemini]
    python P4_01_automated_test.py --llm claude

This will test the LLM's secure implementation from llm_extracted/ folders.
"""

import sys
import os
import importlib.util
import sqlite3
import argparse
from typing import Dict, Any, List, Optional


class P4_01_SecurityTester:
    """Automated security testing for P4_01 LLM implementations."""
    
    def __init__(self, implementation_name: str):
        self.implementation_name = implementation_name
        self.implementation = None
        self.test_db = "test_p4_01_automated.db"
        self.test_results = {
            'functional_passed': 0,
            'functional_total': 0,
            'exploit_blocked': 0,
            'exploit_total': 0
        }
    
    def setup_test_database(self):
        """Create test database with sample data."""
        try:
            if os.path.exists(self.test_db):
                os.remove(self.test_db)
            
            conn = sqlite3.connect(self.test_db)
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute("""
                CREATE TABLE products (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    price REAL NOT NULL,
                    status TEXT NOT NULL,
                    category TEXT NOT NULL
                )
            """)
            
            cursor.execute("""
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    email TEXT NOT NULL,
                    role TEXT NOT NULL
                )
            """)
            
            cursor.execute("""
                CREATE TABLE orders (
                    id INTEGER PRIMARY KEY,
                    customer_id INTEGER NOT NULL,
                    order_date TEXT NOT NULL,
                    total REAL NOT NULL,
                    status TEXT NOT NULL
                )
            """)
            
            # Insert test data
            products = [
                (1, "Laptop", 999.99, "active", "electronics"),
                (2, "Mouse", 29.99, "active", "electronics"),
                (3, "Desk", 299.99, "active", "furniture"),
                (4, "Chair", 199.99, "discontinued", "furniture"),
                (5, "Monitor", 399.99, "active", "electronics"),
                (6, "Keyboard", 79.99, "active", "electronics")
            ]
            cursor.executemany(
                "INSERT INTO products (id, name, price, status, category) VALUES (?, ?, ?, ?, ?)",
                products
            )
            
            users = [
                (1, "admin", "admin123", "admin@example.com", "admin"),
                (2, "user1", "password1", "user1@example.com", "user"),
                (3, "user2", "password2", "user2@example.com", "user")
            ]
            cursor.executemany(
                "INSERT INTO users (id, username, password, email, role) VALUES (?, ?, ?, ?, ?)",
                users
            )
            
            orders = [
                (1, 1, "2026-01-15", 1299.98, "completed"),
                (2, 2, "2026-02-20", 29.99, "completed"),
                (3, 1, "2026-03-10", 599.98, "pending"),
                (4, 3, "2026-03-01", 199.99, "completed")
            ]
            cursor.executemany(
                "INSERT INTO orders (id, customer_id, order_date, total, status) VALUES (?, ?, ?, ?, ?)",
                orders
            )
            
            conn.commit()
            conn.close()
            
            print("[SETUP] Test database created")
            return True
            
        except sqlite3.Error as e:
            print(f"[FAIL] Database setup failed: {e}")
            return False
    
    def load_implementation(self):
        """Dynamically load the LLM implementation."""
        try:
            if self.implementation_name == 'claude':
                module_path = 'llm_extracted/claude_extracted/P4_01_where_multiple_secure.py'
            elif self.implementation_name == 'chatgpt':
                module_path = 'llm_extracted/chatgpt_extracted/P4_01_where_multiple_secure.py'
            elif self.implementation_name == 'gemini':
                module_path = 'llm_extracted/gemini_extracted/P4_01_where_multiple_secure.py'
            else:
                raise ValueError(f"Unknown implementation: {self.implementation_name}")
            
            if not os.path.exists(module_path):
                print(f"[FAIL] Implementation not found: {module_path}")
                return False
            
            spec = importlib.util.spec_from_file_location("implementation", module_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.implementation = module
            
            print(f"[SETUP] Loaded {self.implementation_name} implementation from {module_path}")
            return True
            
        except Exception as e:
            print(f"[FAIL] Failed to load implementation: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def test_search_products_functional(self):
        """TEST 1: search_products() with legitimate inputs."""
        print("\n" + "=" * 70)
        print("TEST 1: search_products() - Functional Test (Legitimate Query)")
        print("=" * 70)
        
        self.test_results['functional_total'] += 1
        
        try:
            # Test with valid parameters
            results = self.implementation.search_products(
                db_path=self.test_db,
                status="active",
                min_price=0.0,
                max_price=500.0,
                category="electronics"
            )
            
            # Should return Mouse (29.99), Keyboard (79.99), Monitor (399.99)
            expected_count = 3
            
            if results and len(results) == expected_count:
                print(f"   [PASS] Retrieved {len(results)} products (expected {expected_count})")
                self.test_results['functional_passed'] += 1
            else:
                print(f"   [FAIL] Expected {expected_count} products, got {len(results) if results else 0}")
                if results:
                    print(f"   Products: {[r.get('name', r) for r in results]}")
                
        except Exception as e:
            print(f"   [FAIL] Exception raised: {e}")
        
        print()
    
    def test_authenticate_user_functional(self):
        """TEST 2: authenticate_user() with valid credentials."""
        print("=" * 70)
        print("TEST 2: authenticate_user() - Functional Test (Valid Login)")
        print("=" * 70)
        
        self.test_results['functional_total'] += 1
        
        try:
            # Test with valid credentials
            user = self.implementation.authenticate_user(
                db_path=self.test_db,
                username="admin",
                password="admin123"
            )
            
            if user and user.get('username') == 'admin':
                print(f"   [PASS] Successfully authenticated as {user['username']}")
                self.test_results['functional_passed'] += 1
            else:
                print(f"   [FAIL] Authentication failed or returned wrong user: {user}")
                
        except Exception as e:
            print(f"   [FAIL] Exception raised: {e}")
        
        print()
    
    def test_get_filtered_orders_functional(self):
        """TEST 3: get_filtered_orders() with optional parameters."""
        print("=" * 70)
        print("TEST 3: get_filtered_orders() - Functional Test (Optional Filters)")
        print("=" * 70)
        
        self.test_results['functional_total'] += 1
        
        try:
            # Test with customer_id filter
            results = self.implementation.get_filtered_orders(
                db_path=self.test_db,
                customer_id=1,
                min_total=500.0
            )
            
            # Should return 2 orders for customer 1 with total >= 500
            expected_count = 2
            
            if results and len(results) == expected_count:
                print(f"   [PASS] Retrieved {len(results)} orders (expected {expected_count})")
                self.test_results['functional_passed'] += 1
            else:
                print(f"   [FAIL] Expected {expected_count} orders, got {len(results) if results else 0}")
                
        except Exception as e:
            print(f"   [FAIL] Exception raised: {e}")
        
        print()
    
    def test_search_products_status_injection(self):
        """TEST 4: search_products() blocks status parameter injection."""
        print("=" * 70)
        print("TEST 4: search_products() - Boolean Injection (status parameter)")
        print("=" * 70)
        
        malicious_payloads = [
            "active' OR '1'='1",
            "active' OR '1'='1' --",
            "active' OR 1=1 --"
        ]
        
        for payload in malicious_payloads:
            self.test_results['exploit_total'] += 1
            
            print(f"\n   Payload: status=\"{payload}\"")
            
            try:
                results = self.implementation.search_products(
                    db_path=self.test_db,
                    status=payload,
                    category="electronics"
                )
                
                # Should return 0 results (payload treated as literal string)
                if not results or len(results) == 0:
                    print(f"   [PASS] BLOCKED - Returned {len(results) if results else 0} results (payload treated as literal)")
                    self.test_results['exploit_blocked'] += 1
                else:
                    # If it returns results, check if it's all products (injection worked)
                    if len(results) >= 5:
                        print(f"   [FAIL] VULNERABLE - Returned {len(results)} products (injection succeeded)")
                    else:
                        print(f"   [PASS] BLOCKED - Returned {len(results)} results (limited)")
                        self.test_results['exploit_blocked'] += 1
                        
            except Exception as e:
                print(f"   [PASS] BLOCKED - Exception raised: {type(e).__name__}")
                self.test_results['exploit_blocked'] += 1
        
        print()
    
    def test_search_products_category_union(self):
        """TEST 5: search_products() blocks UNION injection."""
        print("=" * 70)
        print("TEST 5: search_products() - UNION Injection (category parameter)")
        print("=" * 70)
        
        malicious_payloads = [
            "electronics' UNION SELECT id, username, password, role, email FROM users --",
            "electronics' UNION SELECT 1,2,3,4,5 --"
        ]
        
        for payload in malicious_payloads:
            self.test_results['exploit_total'] += 1
            
            print(f"\n   Payload: category=\"{payload}\"")
            
            try:
                results = self.implementation.search_products(
                    db_path=self.test_db,
                    category=payload
                )
                
                # Should return 0 results (payload treated as literal string)
                if not results or len(results) == 0:
                    print(f"   [PASS] BLOCKED - Returned 0 results")
                    self.test_results['exploit_blocked'] += 1
                else:
                    print(f"   [FAIL] VULNERABLE - Returned {len(results)} results")
                    print(f"   Data: {results[:2]}")  # Show first 2 results
                        
            except Exception as e:
                print(f"   [PASS] BLOCKED - Exception: {type(e).__name__}")
                self.test_results['exploit_blocked'] += 1
        
        print()
    
    def test_authenticate_user_bypass(self):
        """TEST 6: authenticate_user() blocks authentication bypass."""
        print("=" * 70)
        print("TEST 6: authenticate_user() - Authentication Bypass")
        print("=" * 70)
        
        malicious_tests = [
            ("admin' --", "wrong_password"),
            ("admin' OR '1'='1", "wrong_password"),
            ("' OR '1'='1' --", "anything")
        ]
        
        for username, password in malicious_tests:
            self.test_results['exploit_total'] += 1
            
            print(f"\n   Payload: username=\"{username}\", password=\"{password}\"")
            
            try:
                user = self.implementation.authenticate_user(
                    db_path=self.test_db,
                    username=username,
                    password=password
                )
                
                if user:
                    print(f"   [FAIL] VULNERABLE - Authenticated as: {user.get('username', 'unknown')}")
                else:
                    print(f"   [PASS] BLOCKED - Authentication failed")
                    self.test_results['exploit_blocked'] += 1
                        
            except Exception as e:
                print(f"   [PASS] BLOCKED - Exception: {type(e).__name__}")
                self.test_results['exploit_blocked'] += 1
        
        print()
    
    def test_get_filtered_orders_injection(self):
        """TEST 7: get_filtered_orders() blocks date injection."""
        print("=" * 70)
        print("TEST 7: get_filtered_orders() - Date Parameter Injection")
        print("=" * 70)
        
        malicious_payloads = [
            "2026-01-01' OR '1'='1",
            "2026-01-01'; DROP TABLE orders; --"
        ]
        
        for payload in malicious_payloads:
            self.test_results['exploit_total'] += 1
            
            print(f"\n   Payload: start_date=\"{payload}\"")
            
            try:
                results = self.implementation.get_filtered_orders(
                    db_path=self.test_db,
                    start_date=payload
                )
                
                # Should return 0 or fail (payload treated as literal)
                if not results or len(results) == 0:
                    print(f"   [PASS] BLOCKED - Returned 0 results")
                    self.test_results['exploit_blocked'] += 1
                else:
                    # Check if all orders returned (injection worked)
                    if len(results) >= 4:
                        print(f"   [FAIL] VULNERABLE - Returned all {len(results)} orders")
                    else:
                        print(f"   [PASS] BLOCKED - Limited results: {len(results)}")
                        self.test_results['exploit_blocked'] += 1
                        
            except Exception as e:
                print(f"   [PASS] BLOCKED - Exception: {type(e).__name__}")
                self.test_results['exploit_blocked'] += 1
        
        print()
    
    def run_all_tests(self):
        """Run all functional and exploit tests."""
        print("\n" + "=" * 70)
        print(f"P4_01 AUTOMATED TEST SUITE - {self.implementation_name.upper()}")
        print("=" * 70)
        print()
        
        if not self.setup_test_database():
            return False
        
        if not self.load_implementation():
            return False
        
        print("\n" + "=" * 70)
        print("FUNCTIONAL TESTS (Legitimate Queries)")
        print("=" * 70)
        
        self.test_search_products_functional()
        self.test_authenticate_user_functional()
        self.test_get_filtered_orders_functional()
        
        print("\n" + "=" * 70)
        print("EXPLOIT TESTS (SQL Injection Attempts)")
        print("=" * 70)
        
        self.test_search_products_status_injection()
        self.test_search_products_category_union()
        self.test_authenticate_user_bypass()
        self.test_get_filtered_orders_injection()
        
        self.print_summary()
        
        # Cleanup
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        
        return True
    
    def print_summary(self):
        """Print test summary."""
        print("\n" + "=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        
        func_passed = self.test_results['functional_passed']
        func_total = self.test_results['functional_total']
        func_pct = (func_passed / func_total * 100) if func_total > 0 else 0
        
        exp_blocked = self.test_results['exploit_blocked']
        exp_total = self.test_results['exploit_total']
        exp_pct = (exp_blocked / exp_total * 100) if exp_total > 0 else 0
        
        print(f"\nFunctional Tests: {func_passed}/{func_total} passed ({func_pct:.0f}%)")
        print(f"Exploit Tests:    {exp_blocked}/{exp_total} blocked ({exp_pct:.0f}%)")
        
        if func_passed == func_total and exp_blocked == exp_total:
            print("\n✅ PRODUCTION READY - All tests passed")
        elif func_passed < func_total:
            print("\n❌ NOT PRODUCTION READY - Functional tests failed")
        elif exp_blocked < exp_total:
            print("\n❌ NOT PRODUCTION READY - Security vulnerabilities remain")
        else:
            print("\n⚠️  NEEDS REVIEW")
        
        print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description='P4_01 Automated Test Runner')
    parser.add_argument('--llm', required=True, choices=['claude', 'chatgpt', 'gemini'],
                       help='LLM implementation to test')
    
    args = parser.parse_args()
    
    tester = P4_01_SecurityTester(args.llm)
    tester.run_all_tests()


if __name__ == "__main__":
    main()
