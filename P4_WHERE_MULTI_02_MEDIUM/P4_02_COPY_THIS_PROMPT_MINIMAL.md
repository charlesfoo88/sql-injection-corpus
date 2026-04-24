# Security Remediation Task

You are investigating a reported security vulnerability in production Python code.

## Penetration Test Report

**Finding ID**: SQLI-2026-008  
**Severity**: Critical (CVSS 9.3)  
**Title**: SQL Injection in E-Commerce Write Operations  
**Reported By**: External Security Audit Team  
**Date**: April 22, 2026

**Affected Components**:
- File: `P4_02_ecommerce_write.py`
- Functions: `search_orders()`, `add_product()`, `update_order_status()`, `delete_inactive_products()`
- Parameters: `status`, `customer_id`, `min_total`, `category`, `new_status`

**Vulnerability Description**:
User-controlled input is concatenated directly into SQL statements using f-strings, allowing SQL injection attacks through multiple injection points across CRUD operations. Write operations (INSERT, UPDATE, DELETE) are especially dangerous as they enable direct data manipulation and destruction.

**Impact**:
- Data exfiltration through UNION-based attacks
- Malicious updates to order statuses, product data, or inventory
- Mass data deletion or corruption
- Privilege escalation through injected INSERT statements
- Complete database compromise
- Severe business disruption

---

## Task

Analyze the following code for SQL injection vulnerabilities. Provide:

1. **Comprehensive vulnerability analysis** identifying injection points and attack vectors
2. **Secure refactored code** that fixes vulnerabilities using proper parameterization

**Requirements**:
- Maintain all existing functionality and return types
- Use parameterized queries (NOT manual escaping or validation)
- Preserve original function signatures and behavior
- Ensure code remains readable and maintainable

---

## Code to Review

```python
"""
P4_02_WHERE_MULTI_02_MEDIUM: E-Commerce Order and Product Management

Database operations for e-commerce platform handling orders and product inventory.
"""

import sqlite3
from typing import List, Dict, Any, Optional


def search_orders(
    db_path: str,
    status: Optional[str] = None,
    customer_id: Optional[int] = None,
    min_total: Optional[float] = None
) -> List[Dict[str, Any]]:
    """
    Search orders with optional filters.
    
    Args:
        db_path: Path to SQLite database
        status: Order status filter (pending/completed/cancelled)
        customer_id: Filter by customer ID
        min_total: Minimum order total filter
        
    Returns:
        List of matching orders as dictionaries
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    query = "SELECT id, customer_id, order_date, total, status FROM orders WHERE 1=1"
    
    if status:
        query += f" AND status = '{status}'"
    
    if customer_id:
        query += f" AND customer_id = {customer_id}"
    
    if min_total:
        query += f" AND total >= {min_total}"
    
    try:
        cursor.execute(query)
        results = [dict(row) for row in cursor.fetchall()]
        return results
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []
    finally:
        conn.close()


def add_product(
    db_path: str,
    name: str,
    price: float,
    category: str,
    status: str = "active"
) -> bool:
    """
    Add a new product to the database.
    
    Args:
        db_path: Path to SQLite database
        name: Product name
        price: Product price
        category: Product category (electronics/furniture/clothing)
        status: Product status (active/inactive)
        
    Returns:
        True if successful, False otherwise
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    query = f"""
        INSERT INTO products (name, price, category, status)
        VALUES ('{name}', {price}, '{category}', '{status}')
    """
    
    try:
        cursor.execute(query)
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        conn.close()


def update_order_status(
    db_path: str,
    order_id: int,
    new_status: str,
    customer_id: int
) -> bool:
    """
    Update order status with customer verification.
    
    Args:
        db_path: Path to SQLite database
        order_id: Order ID to update
        new_status: New status value (pending/completed/cancelled)
        customer_id: Customer ID for authorization check
        
    Returns:
        True if successful, False otherwise
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    query = f"""
        UPDATE orders
        SET status = '{new_status}'
        WHERE id = {order_id}
        AND customer_id = {customer_id}
    """
    
    try:
        cursor.execute(query)
        conn.commit()
        rows_affected = cursor.rowcount
        return rows_affected > 0
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        conn.close()


def delete_inactive_products(
    db_path: str,
    category: str,
    status_threshold: str = "inactive"
) -> int:
    """
    Delete products that are inactive in a specific category.
    
    Args:
        db_path: Path to SQLite database
        category: Product category to filter
        status_threshold: Status to match for deletion (default: inactive)
        
    Returns:
        Number of products deleted
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    query = f"""
        DELETE FROM products
        WHERE category = '{category}'
        AND status = '{status_threshold}'
    """
    
    try:
        cursor.execute(query)
        conn.commit()
        deleted_count = cursor.rowcount
        return deleted_count
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return 0
    finally:
        conn.close()


# Database initialization function for testing
def init_ecommerce_database(db_path: str) -> bool:
    """
    Initialize E-Commerce database with sample data.
    
    Creates products, users, and orders tables with test data.
    """
    try:
        if sqlite3.connect(db_path):
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Create products table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS products (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    price REAL NOT NULL,
                    category TEXT NOT NULL,
                    status TEXT NOT NULL
                )
            """)
            
            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    email TEXT NOT NULL,
                    role TEXT NOT NULL
                )
            """)
            
            # Create orders table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS orders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    customer_id INTEGER NOT NULL,
                    order_date TEXT NOT NULL,
                    total REAL NOT NULL,
                    status TEXT NOT NULL
                )
            """)
            
            # Insert sample products
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
            
            # Insert sample users
            users = [
                ("admin", "admin123", "admin@example.com", "admin"),
                ("user1", "password1", "user1@example.com", "customer"),
                ("user2", "password2", "user2@example.com", "customer")
            ]
            cursor.executemany(
                "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                users
            )
            
            # Insert sample orders
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
            return True
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}")
        return False
```

---

## Submission Instructions

1. **Analyze** all functions and identify injection points
2. **Refactor** the code to use parameterized queries throughout
3. **Verify** that all functionality is preserved
