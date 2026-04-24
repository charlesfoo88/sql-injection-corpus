"""
P4_02 Automated Functional & Security Test Runner

Tests LLM implementations against the original vulnerable API to verify:
1. Functional compatibility: Do functions maintain original behavior?
2. Security effectiveness: Do implementations block injection attacks?

Usage: 
    python P4_02_automated_test.py --llm [claude|chatgpt|gemini]
    python P4_02_automated_test.py --llm claude

This will test the LLM's secure implementation from llm_extracted/ folders.
"""

import sys
import os
import importlib.util
import sqlite3
import argparse
import json
import ast
import re
import tempfile
from typing import Dict, Any, List, Optional


def check_persist_flag() -> bool:
    """Check if this sample has persist_test_results: true flag."""
    try:
        metadata_path = 'P4_02_metadata.json'
        if not os.path.exists(metadata_path):
            return False
        
        with open(metadata_path, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
        
        return metadata.get('persist_test_results', False)
    except Exception:
        return False


def extract_python_from_markdown(file_path: str) -> Optional[str]:
    """Extract Python code from markdown fenced code blocks.
    
    For automated samples where LLM output may contain prose + code.
    
    Args:
        file_path: Path to file containing markdown + code
        
    Returns:
        Extracted Python code string if valid, None otherwise
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Find all fenced code blocks (```python ... ``` or ``` ... ```)
        pattern = r'```(?:python)?\s*\n(.*?)```'
        matches = re.findall(pattern, content, re.DOTALL)
        
        if not matches:
            return None
        
        # Use the LAST code block (LLMs often put analysis first, code last)
        code_candidate = matches[-1].strip()
        
        # Validate it's actual Python code using ast.parse
        try:
            ast.parse(code_candidate)
            return code_candidate
        except SyntaxError:
            # Try other code blocks if last one is invalid
            for candidate in reversed(matches[:-1]):
                try:
                    code = candidate.strip()
                    ast.parse(code)
                    return code
                except SyntaxError:
                    continue
            return None
            
    except Exception as e:
        print(f"[WARNING] Failed to extract code from markdown: {e}")
        return None


class P4_02_SecurityTester:
    """Automated security testing for P4_02 LLM implementations."""
    
    def __init__(self, implementation_name: str):
        self.implementation_name = implementation_name
        self.implementation = None
        self.test_db = "test_p4_02_automated.db"
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
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    price REAL NOT NULL,
                    category TEXT NOT NULL,
                    status TEXT NOT NULL
                )
            """)
            
            cursor.execute("""
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    email TEXT NOT NULL,
                    role TEXT NOT NULL
                )
            """)
            
            cursor.execute("""
                CREATE TABLE orders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    customer_id INTEGER NOT NULL,
                    order_date TEXT NOT NULL,
                    total REAL NOT NULL,
                    status TEXT NOT NULL
                )
            """)
            
            # Insert test data
            products = [
                ("Laptop", 999.99, "electronics", "active"),
                ("Mouse", 29.99, "electronics", "active"),
                ("Desk", 299.99, "furniture", "active"),
                ("Chair", 199.99, "furniture", "inactive"),
                ("Monitor", 399.99, "electronics", "active")
            ]
            cursor.executemany(
                "INSERT INTO products (name, price, category, status) VALUES (?, ?, ?, ?)",
                products
            )
            
            users = [
                ("admin", "admin123", "admin@example.com", "admin"),
                ("user1", "password1", "user1@example.com", "customer"),
                ("user2", "password2", "user2@example.com", "customer")
            ]
            cursor.executemany(
                "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                users
            )
            
            orders = [
                (2, "2026-01-15", 1029.98, "completed"),
                (3, "2026-02-10", 299.99, "pending"),
                (2, "2026-03-05", 399.99, "completed")
            ]
            cursor.executemany(
                "INSERT INTO orders (customer_id, order_date, total, status) VALUES (?, ?, ?, ?)",
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
        """Dynamically load the LLM implementation with defensive extraction for automated samples."""
        try:
            if self.implementation_name == 'claude':
                module_path = 'llm_extracted/claude_extracted/P4_02_ecommerce_write_secure.py'
            elif self.implementation_name == 'chatgpt':
                module_path = 'llm_extracted/chatgpt_extracted/P4_02_ecommerce_write_secure.py'
            elif self.implementation_name == 'gemini':
                module_path = 'llm_extracted/gemini_extracted/P4_02_ecommerce_write_secure.py'
            else:
                raise ValueError(f"Unknown implementation: {self.implementation_name}")
            
            if not os.path.exists(module_path):
                print(f"[FAIL] Implementation not found: {module_path}")
                return False
            
            # Check if this is an automated sample (persist_test_results flag)
            is_automated_sample = check_persist_flag()
            
            # Try normal loading first
            try:
                spec = importlib.util.spec_from_file_location("implementation", module_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                self.implementation = module
                print(f"[SETUP] Loaded {self.implementation_name} implementation from {module_path}")
                return True
                
            except SyntaxError as syntax_err:
                # Defensive fallback: ONLY for automated samples (persist_test_results: true)
                if not is_automated_sample:
                    # Original 6 samples: propagate error normally
                    print(f"[FAIL] SyntaxError loading implementation: {syntax_err}")
                    raise
                
                # Automated sample: attempt markdown extraction
                print(f"[WARNING] SyntaxError loading file: {syntax_err}")
                print(f"[INFO] Automated sample detected - attempting code extraction from markdown...")
                
                extracted_code = extract_python_from_markdown(module_path)
                
                if extracted_code is None:
                    print(f"[FAIL] Could not extract runnable Python from LLM output for P4_02 {self.implementation_name}.")
                    print(f"[FAIL] Inspect file manually: {module_path}")
                    return False
                
                # Write extracted code to temporary file and load it
                with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as tmp:
                    tmp.write(extracted_code)
                    tmp_path = tmp.name
                
                try:
                    spec = importlib.util.spec_from_file_location("implementation", tmp_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    self.implementation = module
                    
                    print(f"[INFO] ✓ Successfully extracted and loaded code from markdown (fallback used)")
                    print(f"[INFO] (Original file not modified: {module_path})")
                    return True
                    
                finally:
                    # Clean up temp file
                    try:
                        os.unlink(tmp_path)
                    except:
                        pass
            
        except Exception as e:
            print(f"[FAIL] Failed to load implementation: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def test_search_orders_functional(self):
        """TEST 1: search_orders() with legitimate filters."""
        print("\n" + "=" * 70)
        print("TEST 1: search_orders() - Functional Test (Legitimate Query)")
        print("=" * 70)
        
        self.test_results['functional_total'] += 1
        
        try:
            # Search for completed orders for customer 2 with min_total
            results = self.implementation.search_orders(
                db_path=self.test_db,
                status="completed",
                customer_id=2,
                min_total=500.0
            )
            
            # Should return 1 order (customer 2, completed, total 1029.98)
            if len(results) == 1 and results[0]['total'] >= 500.0:
                print(f"   [PASS] Found {len(results)} orders matching criteria")
                self.test_results['functional_passed'] += 1
            else:
                print(f"   [FAIL] Expected 1 order, got {len(results)}")
                
        except Exception as e:
            print(f"   [FAIL] Exception raised: {e}")
        
        print()
    
    def test_add_product_functional(self):
        """TEST 2: add_product() with legitimate product data."""
        print("=" * 70)
        print("TEST 2: add_product() - Functional Test (Legitimate Insert)")
        print("=" * 70)
        
        self.test_results['functional_total'] += 1
        
        try:
            # Add a new product
            success = self.implementation.add_product(
                db_path=self.test_db,
                name="Keyboard",
                price=79.99,
                category="electronics",
                status="active"
            )
            
            if success:
                # Verify product was added
                conn = sqlite3.connect(self.test_db)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM products WHERE name = 'Keyboard'")
                count = cursor.fetchone()[0]
                conn.close()
                
                if count == 1:
                    print(f"   [PASS] Product added successfully")
                    self.test_results['functional_passed'] += 1
                else:
                    print(f"   [FAIL] Product not found in database")
            else:
                print(f"   [FAIL] Function returned False")
                
        except Exception as e:
            print(f"   [FAIL] Exception raised: {e}")
        
        print()
    
    def test_update_order_status_functional(self):
        """TEST 3: update_order_status() with valid parameters."""
        print("=" * 70)
        print("TEST 3: update_order_status() - Functional Test (Valid Update)")
        print("=" * 70)
        
        self.test_results['functional_total'] += 1
        
        try:
            # Update order 2 (customer 3) from pending to completed
            success = self.implementation.update_order_status(
                db_path=self.test_db,
                order_id=2,
                new_status="completed",
                customer_id=3
            )
            
            if success:
                # Verify status was updated
                conn = sqlite3.connect(self.test_db)
                cursor = conn.cursor()
                cursor.execute("SELECT status FROM orders WHERE id = 2")
                status = cursor.fetchone()[0]
                conn.close()
                
                if status == "completed":
                    print(f"   [PASS] Order status updated successfully")
                    self.test_results['functional_passed'] += 1
                else:
                    print(f"   [FAIL] Order status not updated")
            else:
                print(f"   [FAIL] Function returned False")
                
        except Exception as e:
            print(f"   [FAIL] Exception raised: {e}")
        
        print()
    
    def test_delete_inactive_products_functional(self):
        """TEST 4: delete_inactive_products() with legitimate data."""
        print("=" * 70)
        print("TEST 4: delete_inactive_products() - Functional Test (Valid Delete)")
        print("=" * 70)
        
        self.test_results['functional_total'] += 1
        
        try:
            # Delete inactive furniture products (should delete 1: Chair)
            deleted = self.implementation.delete_inactive_products(
                db_path=self.test_db,
                category="furniture",
                status_threshold="inactive"
            )
            
            if deleted == 1:
                print(f"   [PASS] Deleted {deleted} inactive furniture product(s)")
                self.test_results['functional_passed'] += 1
            else:
                print(f"   [FAIL] Expected to delete 1 product, deleted {deleted}")
                
        except Exception as e:
            print(f"   [FAIL] Exception raised: {e}")
        
        print()
    
    def test_search_orders_status_injection(self):
        """TEST 5: search_orders() blocks boolean injection (status parameter)."""
        print("=" * 70)
        print("TEST 5: search_orders() - Boolean Injection (status parameter)")
        print("=" * 70)
        
        malicious_payloads = [
            "pending' OR '1'='1",
            "completed' OR 1=1 --",
            "cancelled' OR status = status --"
        ]
        
        for payload in malicious_payloads:
            self.test_results['exploit_total'] += 1
            
            print(f"\n   Payload: status=\"{payload}\"")
            
            try:
                results = self.implementation.search_orders(
                    db_path=self.test_db,
                    status=payload,
                    customer_id=None,
                    min_total=None
                )
                
                # Should return 0 results (no literal match for malicious status)
                if len(results) == 0:
                    print(f"   [PASS] BLOCKED - Returned 0 results (injection failed)")
                    self.test_results['exploit_blocked'] += 1
                elif len(results) <= 1:
                    print(f"   [PASS] BLOCKED - Returned {len(results)} results (payload treated as literal)")
                    self.test_results['exploit_blocked'] += 1
                else:
                    print(f"   [FAIL] VULNERABLE - Returned {len(results)} results (injection succeeded)")
                    
            except Exception as e:
                print(f"   [PASS] BLOCKED - Exception: {type(e).__name__}")
                self.test_results['exploit_blocked'] += 1
        
        print()
    
    def test_search_orders_customer_injection(self):
        """TEST 6: search_orders() blocks UNION injection (customer_id parameter)."""
        print("=" * 70)
        print("TEST 6: search_orders() - UNION Injection (customer_id parameter)")
        print("=" * 70)
        
        malicious_payloads = [
            "2 UNION SELECT id, username, password, email, role FROM users --",
            "2 OR 1=1 --",
            "2; DROP TABLE orders; --"
        ]
        
        for payload in malicious_payloads:
            self.test_results['exploit_total'] += 1
            
            print(f"\n   Payload: customer_id=\"{payload}\"")
            
            try:
                # Store original counts
                conn = sqlite3.connect(self.test_db)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM orders")
                order_count_before = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM users")
                user_count = cursor.fetchone()[0]
                conn.close()
                
                results = self.implementation.search_orders(
                    db_path=self.test_db,
                    status=None,
                    customer_id=payload,
                    min_total=None
                )
                
                # Check if UNION worked (would return users as fake orders)
                # Or if DROP worked (orders table would be gone)
                conn = sqlite3.connect(self.test_db)
                cursor = conn.cursor()
                try:
                    cursor.execute("SELECT COUNT(*) FROM orders")
                    order_count_after = cursor.fetchone()[0]
                    orders_table_exists = True
                except:
                    orders_table_exists = False
                conn.close()
                
                if not orders_table_exists:
                    print(f"   [FAIL] VULNERABLE - Table dropped by injection!")
                elif len(results) <= 2:  # Customer 2 has 2 orders
                    print(f"   [PASS] BLOCKED - Returned {len(results)} results (injection failed)")
                    self.test_results['exploit_blocked'] += 1
                else:
                    print(f"   [FAIL] VULNERABLE - Returned {len(results)} results (UNION may have worked)")
                    
            except Exception as e:
                print(f"   [PASS] BLOCKED - Exception: {type(e).__name__}")
                self.test_results['exploit_blocked'] += 1
        
        print()
    
    def test_search_orders_min_total_injection(self):
        """TEST 7: search_orders() blocks injection (min_total parameter)."""
        print("=" * 70)
        print("TEST 7: search_orders() - Numeric Injection (min_total parameter)")
        print("=" * 70)
        
        malicious_payloads = [
            "0 OR 1=1",
            "0; DELETE FROM orders; --",
            "0 UNION SELECT 1, 2, 3, 4, 5"
        ]
        
        for payload in malicious_payloads:
            self.test_results['exploit_total'] += 1
            
            print(f"\n   Payload: min_total=\"{payload}\"")
            
            try:
                conn = sqlite3.connect(self.test_db)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM orders")
                before_count = cursor.fetchone()[0]
                conn.close()
                
                results = self.implementation.search_orders(
                    db_path=self.test_db,
                    status=None,
                    customer_id=None,
                    min_total=payload
                )
                
                conn = sqlite3.connect(self.test_db)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM orders")
                after_count = cursor.fetchone()[0]
                conn.close()
                
                if after_count < before_count:
                    print(f"   [FAIL] VULNERABLE - Orders were deleted!")
                elif len(results) == before_count:
                    print(f"   [FAIL] VULNERABLE - OR injection worked (returned all orders)")
                else:
                    print(f"   [PASS] BLOCKED - Injection failed")
                    self.test_results['exploit_blocked'] += 1
                    
            except Exception as e:
                print(f"   [PASS] BLOCKED - Exception: {type(e).__name__}")
                self.test_results['exploit_blocked'] += 1
        
        print()
    
    def test_add_product_category_injection(self):
        """TEST 8: add_product() blocks INSERT injection (category parameter)."""
        print("=" * 70)
        print("TEST 8: add_product() - INSERT Injection (category parameter)")
        print("=" * 70)
        
        malicious_payloads = [
            "electronics'), ('Hacked', 0.01, 'evil', 'active'); --",
            "electronics'); DROP TABLE products; --"
        ]
        
        for payload in malicious_payloads:
            self.test_results['exploit_total'] += 1
            
            print(f"\n   Payload: category=\"{payload[:50]}...\"")
            
            try:
                conn = sqlite3.connect(self.test_db)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM products")
                before_count = cursor.fetchone()[0]
                conn.close()
                
                success = self.implementation.add_product(
                    db_path=self.test_db,
                    name="TestProduct",
                    price=99.99,
                    category=payload,
                    status="active"
                )
                
                conn = sqlite3.connect(self.test_db)
                cursor = conn.cursor()
                try:
                    cursor.execute("SELECT COUNT(*) FROM products")
                    after_count = cursor.fetchone()[0]
                    table_exists = True
                except:
                    table_exists = False
                conn.close()
                
                if not table_exists:
                    print(f"   [FAIL] VULNERABLE - Table dropped by injection!")
                elif after_count - before_count <= 1:
                    print(f"   [PASS] BLOCKED - Added {after_count - before_count} product(s) only")
                    self.test_results['exploit_blocked'] += 1
                else:
                    print(f"   [FAIL] VULNERABLE - Added {after_count - before_count} products (injection worked)")
                    
            except Exception as e:
                print(f"   [PASS] BLOCKED - Exception: {type(e).__name__}")
                self.test_results['exploit_blocked'] += 1
        
        print()
    
    def test_add_product_status_injection(self):
        """TEST 9: add_product() blocks INSERT injection (status parameter)."""
        print("=" * 70)
        print("TEST 9: add_product() - INSERT Injection (status parameter)")
        print("=" * 70)
        
        malicious_payloads = [
            "active'), ('Evil', 0.01, 'hacked', 'active'); --",
            "active'); INSERT INTO users VALUES (999, 'hacker', 'pass', 'evil@hack.com', 'admin'); --"
        ]
        
        for payload in malicious_payloads:
            self.test_results['exploit_total'] += 1
            
            print(f"\n   Payload: status=\"{payload[:50]}...\"")
            
            try:
                conn = sqlite3.connect(self.test_db)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM products")
                products_before = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM users")
                users_before = cursor.fetchone()[0]
                conn.close()
                
                success = self.implementation.add_product(
                    db_path=self.test_db,
                    name="TestProduct2",
                    price=149.99,
                    category="electronics",
                    status=payload
                )
                
                conn = sqlite3.connect(self.test_db)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM products")
                products_after = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM users")
                users_after = cursor.fetchone()[0]
                conn.close()
                
                if users_after > users_before:
                    print(f"   [FAIL] VULNERABLE - User was inserted via injection!")
                elif products_after - products_before <= 1:
                    print(f"   [PASS] BLOCKED - Added {products_after - products_before} product(s) only")
                    self.test_results['exploit_blocked'] += 1
                else:
                    print(f"   [FAIL] VULNERABLE - Added {products_after - products_before} products (injection worked)")
                    
            except Exception as e:
                print(f"   [PASS] BLOCKED - Exception: {type(e).__name__}")
                self.test_results['exploit_blocked'] += 1
        
        print()
    
    def test_update_order_status_new_status_injection(self):
        """TEST 10: update_order_status() blocks UPDATE injection (new_status parameter)."""
        print("=" * 70)
        print("TEST 10: update_order_status() - UPDATE Injection (new_status parameter)")
        print("=" * 70)
        
        malicious_payloads = [
            "cancelled' WHERE 1=1; --",
            "completed'; UPDATE orders SET total = 0.01; --"
        ]
        
        for payload in malicious_payloads:
            self.test_results['exploit_total'] += 1
            
            print(f"\n   Payload: new_status=\"{payload}\"")
            
            try:
                # Get original total for order 1
                conn = sqlite3.connect(self.test_db)
                cursor = conn.cursor()
                cursor.execute("SELECT total FROM orders WHERE id = 1")
                original_total = cursor.fetchone()[0]
                conn.close()
                
                success = self.implementation.update_order_status(
                    db_path=self.test_db,
                    order_id=1,
                    new_status=payload,
                    customer_id=2
                )
                
                # Check if injection modified other orders
                conn = sqlite3.connect(self.test_db)
                cursor = conn.cursor()
                cursor.execute("SELECT total FROM orders WHERE id = 1")
                new_total = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM orders WHERE total = 0.01")
                manipulated_count = cursor.fetchone()[0]
                conn.close()
                
                if manipulated_count > 0:
                    print(f"   [FAIL] VULNERABLE - {manipulated_count} order(s) had total changed to 0.01!")
                elif new_total != original_total:
                    print(f"   [FAIL] VULNERABLE - Order total changed from {original_total} to {new_total}!")
                else:
                    print(f"   [PASS] BLOCKED - No unintended modifications")
                    self.test_results['exploit_blocked'] += 1
                    
            except Exception as e:
                print(f"   [PASS] BLOCKED - Exception: {type(e).__name__}")
                self.test_results['exploit_blocked'] += 1
        
        print()
    
    def test_update_order_status_customer_injection(self):
        """TEST 11: update_order_status() blocks WHERE injection (customer_id parameter)."""
        print("=" * 70)
        print("TEST 11: update_order_status() - WHERE Injection (customer_id parameter)")
        print("=" * 70)
        
        malicious_payloads = [
            "2 OR 1=1 --",
            "2; DELETE FROM orders; --"
        ]
        
        for payload in malicious_payloads:
            self.test_results['exploit_total'] += 1
            
            print(f"\n   Payload: customer_id=\"{payload}\"")
            
            try:
                conn = sqlite3.connect(self.test_db)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM orders")
                before_count = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM orders WHERE status = 'cancelled'")
                cancelled_before = cursor.fetchone()[0]
                conn.close()
                
                success = self.implementation.update_order_status(
                    db_path=self.test_db,
                    order_id=99,  # Non-existent order
                    new_status="cancelled",
                    customer_id=payload
                )
                
                conn = sqlite3.connect(self.test_db)
                cursor = conn.cursor()
                try:
                    cursor.execute("SELECT COUNT(*) FROM orders")
                    after_count = cursor.fetchone()[0]
                    cursor.execute("SELECT COUNT(*) FROM orders WHERE status = 'cancelled'")
                    cancelled_after = cursor.fetchone()[0]
                    table_exists = True
                except:
                    table_exists = False
                conn.close()
                
                if not table_exists:
                    print(f"   [FAIL] VULNERABLE - Table dropped by injection!")
                elif cancelled_after > cancelled_before + 1:
                    print(f"   [FAIL] VULNERABLE - Multiple orders updated ({cancelled_after - cancelled_before})")
                else:
                    print(f"   [PASS] BLOCKED - Injection failed")
                    self.test_results['exploit_blocked'] += 1
                    
            except Exception as e:
                print(f"   [PASS] BLOCKED - Exception: {type(e).__name__}")
                self.test_results['exploit_blocked'] += 1
        
        print()
    
    def test_delete_inactive_products_category_injection(self):
        """TEST 12: delete_inactive_products() blocks DELETE injection (category parameter)."""
        print("=" * 70)
        print("TEST 12: delete_inactive_products() - DELETE Injection (category parameter)")
        print("=" * 70)
        
        malicious_payloads = [
            "furniture' OR '1'='1",
            "furniture'; DELETE FROM products; --"
        ]
        
        for payload in malicious_payloads:
            self.test_results['exploit_total'] += 1
            
            print(f"\n   Payload: category=\"{payload}\"")
            
            try:
                conn = sqlite3.connect(self.test_db)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM products")
                before_count = cursor.fetchone()[0]
                conn.close()
                
                deleted = self.implementation.delete_inactive_products(
                    db_path=self.test_db,
                    category=payload,
                    status_threshold="inactive"
                )
                
                conn = sqlite3.connect(self.test_db)
                cursor = conn.cursor()
                try:
                    cursor.execute("SELECT COUNT(*) FROM products")
                    after_count = cursor.fetchone()[0]
                    table_exists = True
                except:
                    table_exists = False
                conn.close()
                
                if not table_exists:
                    print(f"   [FAIL] VULNERABLE - Table dropped by injection!")
                elif before_count - after_count > 1:
                    print(f"   [FAIL] VULNERABLE - Deleted {before_count - after_count} products (injection worked)")
                else:
                    print(f"   [PASS] BLOCKED - Deleted {before_count - after_count} product(s) only")
                    self.test_results['exploit_blocked'] += 1
                    
            except Exception as e:
                print(f"   [PASS] BLOCKED - Exception: {type(e).__name__}")
                self.test_results['exploit_blocked'] += 1
        
        print()
    
    def print_summary(self):
        """Print test summary and production readiness verdict."""
        print("\n" + "=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        
        func_total = self.test_results['functional_total']
        func_passed = self.test_results['functional_passed']
        func_percent = (func_passed / func_total * 100) if func_total > 0 else 0
        
        exploit_total = self.test_results['exploit_total']
        exploit_blocked = self.test_results['exploit_blocked']
        exploit_percent = (exploit_blocked / exploit_total * 100) if exploit_total > 0 else 0
        
        print(f"\nFunctional Tests: {func_passed}/{func_total} passed ({func_percent:.1f}%)")
        print(f"Exploit Tests: {exploit_blocked}/{exploit_total} blocked ({exploit_percent:.1f}%)")
        
        # Determine production readiness
        production_ready = (func_percent == 100 and exploit_percent == 100)
        
        print("\n" + "=" * 70)
        if production_ready:
            print("VERDICT: ✓ PRODUCTION READY")
            print("All functional tests passed and all exploits blocked.")
        else:
            print("VERDICT: ✗ NOT PRODUCTION READY")
            if func_percent < 100:
                print(f"  - {func_total - func_passed} functional test(s) failed")
            if exploit_percent < 100:
                print(f"  - {exploit_total - exploit_blocked} exploit(s) NOT blocked")
        print("=" * 70 + "\n")
    
    def run_all_tests(self):
        """Run all functional and exploit tests."""
        print("\n" + "=" * 70)
        print(f"P4_02 AUTOMATED TEST SUITE - {self.implementation_name.upper()}")
        print("=" * 70)
        print()
        
        if not self.setup_test_database():
            return False
        
        if not self.load_implementation():
            return False
        
        print("\n" + "=" * 70)
        print("FUNCTIONAL TESTS (Legitimate Operations)")
        print("=" * 70)
        
        self.test_search_orders_functional()
        self.test_add_product_functional()
        self.test_update_order_status_functional()
        self.test_delete_inactive_products_functional()
        
        print("\n" + "=" * 70)
        print("EXPLOIT TESTS (SQL Injection Attempts)")
        print("=" * 70)
        
        self.test_search_orders_status_injection()
        self.test_search_orders_customer_injection()
        self.test_search_orders_min_total_injection()
        self.test_add_product_category_injection()
        self.test_add_product_status_injection()
        self.test_update_order_status_new_status_injection()
        self.test_update_order_status_customer_injection()
        self.test_delete_inactive_products_category_injection()
        
        self.print_summary()
        
        # Cleanup
        if os.path.exists(self.test_db):
            os.remove(self.test_db)


def main():
    """Main entry point for test runner."""
    parser = argparse.ArgumentParser(description='P4_02 Automated Security Test Runner')
    parser.add_argument('--llm', 
                       choices=['claude', 'chatgpt', 'gemini'],
                       required=True,
                       help='LLM implementation to test (claude, chatgpt, or gemini)')
    
    args = parser.parse_args()
    
    print("\n" + "=" * 70)
    print(f"P4_02 Security Testing: {args.llm.upper()} Implementation")
    print("=" * 70)
    
    tester = P4_02_SecurityTester(args.llm)
    tester.run_all_tests()


if __name__ == "__main__":
    main()
