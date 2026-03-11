"""
P4_01_WHERE_MULTI_01_MEDIUM: SQL Injection via WHERE Clause with Multiple Conditions

VULNERABILITY PATTERN: WHERE Multiple Conditions (P4 Pattern)
DIFFICULTY: Medium
INJECTION POINTS: 6 total (status, min_price, max_price, category, username, password)

This code demonstrates SQL injection through dynamic WHERE clause construction.
Multiple user-controlled values are directly inserted into WHERE conditions using
f-strings, creating multiple injection points.

WHY THIS IS VULNERABLE:
- f-strings in WHERE clause allow SQL syntax injection
- Multiple conditions concatenated without parameterization
- Each user input is a potential injection point
- No parameter binding used

CORRECT FIX:
- Use parameterized queries with %s placeholders
- Pass all user input as parameters to cursor.execute()
- Example: cursor.execute("WHERE status = %s AND price >= %s", (status, min_price))
"""

import sqlite3
from typing import List, Dict, Any, Optional


def search_products(
    db_path: str,
    status: str = "active",
    min_price: float = 0.0,
    max_price: float = 999999.99,
    category: str = "all"
) -> List[Dict[str, Any]]:
    """
    Search products with multiple WHERE conditions.
    
    VULNERABLE INJECTION POINTS (4):
    - status parameter (line ~65)
    - min_price parameter (line ~65)
    - max_price parameter (line ~65)
    - category parameter (line ~67)
    
    Args:
        db_path: Path to SQLite database
        status: Product status filter (active/inactive/discontinued)
        min_price: Minimum price filter
        max_price: Maximum price filter
        category: Product category filter
        
    Returns:
        List of matching products as dictionaries
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # VULNERABILITY: Direct string interpolation in WHERE clause
    # All user inputs (status, min_price, max_price, category) are vulnerable
    query = f"""
        SELECT id, name, price, status, category
        FROM products
        WHERE status = '{status}'
        AND price >= {min_price}
        AND price <= {max_price}
    """
    
    # Add category filter if specified
    if category != "all":
        query += f" AND category = '{category}'"
    
    try:
        cursor.execute(query)
        results = [dict(row) for row in cursor.fetchall()]
        return results
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []
    finally:
        conn.close()


def authenticate_user(db_path: str, username: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Authenticate user with username and password.
    
    VULNERABLE INJECTION POINTS (2):
    - username parameter (line ~97)
    - password parameter (line ~97)
    
    Classic authentication bypass vulnerability.
    
    Args:
        db_path: Path to SQLite database
        username: User's username
        password: User's password
        
    Returns:
        User record if authenticated, None otherwise
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # VULNERABILITY: Classic SQL injection in authentication
    # Both username and password can be injected
    query = f"""
        SELECT id, username, email, role
        FROM users
        WHERE username = '{username}'
        AND password = '{password}'
    """
    
    try:
        cursor.execute(query)
        result = cursor.fetchone()
        return dict(result) if result else None
    except sqlite3.Error as e:
        print(f"Authentication error: {e}")
        return None
    finally:
        conn.close()


def get_filtered_orders(
    db_path: str,
    customer_id: Optional[int] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    min_total: Optional[float] = None
) -> List[Dict[str, Any]]:
    """
    Get orders with optional filters.
    
    DEMONSTRATION: Shows conditional WHERE clause building
    This function shows a more complex scenario where WHERE conditions
    are built dynamically based on which parameters are provided.
    
    Args:
        db_path: Path to SQLite database
        customer_id: Filter by customer ID
        start_date: Filter orders after this date (YYYY-MM-DD)
        end_date: Filter orders before this date (YYYY-MM-DD)
        min_total: Filter by minimum order total
        
    Returns:
        List of matching orders
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Start with base query
    query = "SELECT * FROM orders WHERE 1=1"
    
    # Build WHERE conditions dynamically
    # VULNERABILITY: Each condition uses f-string interpolation
    if customer_id is not None:
        query += f" AND customer_id = {customer_id}"
    
    if start_date:
        query += f" AND order_date >= '{start_date}'"
    
    if end_date:
        query += f" AND order_date <= '{end_date}'"
    
    if min_total is not None:
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


# Database initialization helper
def init_test_database(db_path: str):
    """Initialize test database with sample data."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create products table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            status TEXT NOT NULL,
            category TEXT NOT NULL
        )
    """)
    
    # Create users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)
    
    # Create orders table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            customer_id INTEGER NOT NULL,
            order_date TEXT NOT NULL,
            total REAL NOT NULL,
            status TEXT NOT NULL
        )
    """)
    
    # Insert sample products
    products = [
        (1, "Laptop", 999.99, "active", "electronics"),
        (2, "Mouse", 29.99, "active", "electronics"),
        (3, "Desk", 299.99, "active", "furniture"),
        (4, "Chair", 199.99, "discontinued", "furniture"),
        (5, "Monitor", 399.99, "active", "electronics")
    ]
    cursor.executemany(
        "INSERT OR REPLACE INTO products (id, name, price, status, category) VALUES (?, ?, ?, ?, ?)",
        products
    )
    
    # Insert sample users
    users = [
        (1, "admin", "admin123", "admin@example.com", "admin"),
        (2, "user1", "password1", "user1@example.com", "user"),
        (3, "user2", "password2", "user2@example.com", "user")
    ]
    cursor.executemany(
        "INSERT OR REPLACE INTO users (id, username, password, email, role) VALUES (?, ?, ?, ?, ?)",
        users
    )
    
    # Insert sample orders
    orders = [
        (1, 1, "2026-01-15", 1299.98, "completed"),
        (2, 2, "2026-02-20", 29.99, "completed"),
        (3, 1, "2026-03-10", 599.98, "pending")
    ]
    cursor.executemany(
        "INSERT OR REPLACE INTO orders (id, customer_id, order_date, total, status) VALUES (?, ?, ?, ?, ?)",
        orders
    )
    
    conn.commit()
    conn.close()
    print(f"Test database initialized: {db_path}")


if __name__ == "__main__":
    # Initialize test database
    TEST_DB = "test_p4_01.db"
    init_test_database(TEST_DB)
    
    # Test legitimate queries
    print("\n=== Legitimate Query Tests ===")
    
    print("\n1. Search active electronics:")
    results = search_products(TEST_DB, status="active", category="electronics", max_price=500)
    for product in results:
        print(f"  - {product['name']}: ${product['price']}")
    
    print("\n2. Authenticate valid user:")
    user = authenticate_user(TEST_DB, "admin", "admin123")
    print(f"  Logged in: {user['username'] if user else 'Failed'}")
    
    print("\n3. Get customer orders:")
    orders = get_filtered_orders(TEST_DB, customer_id=1, min_total=500)
    print(f"  Found {len(orders)} orders")
    
    print("\n=== SQL Injection Attack Examples (Demonstration) ===")
    print("WARNING: These demonstrate vulnerabilities - DO NOT use in production!\n")
    
    # Attack 1: Boolean injection
    print("Attack 1: Boolean injection in status parameter")
    print("Payload: status=\"active' OR '1'='1\"")
    results = search_products(TEST_DB, status="active' OR '1'='1", category="electronics")
    print(f"Result: Returned {len(results)} products (should be 3, got all products)\n")
    
    # Attack 2: Authentication bypass
    print("Attack 2: Authentication bypass")
    print("Payload: username=\"admin' --\"")
    user = authenticate_user(TEST_DB, "admin' --", "wrong_password")
    print(f"Result: {'SUCCESS - Bypassed password check!' if user else 'Failed'}\n")
    
    # Attack 3: UNION injection
    print("Attack 3: UNION injection in category")
    print("Payload: category=\"electronics' UNION SELECT id, password, email, role, 'stolen' FROM users --\"")
    results = search_products(TEST_DB, category="electronics' UNION SELECT id, password, email, role, 'stolen' FROM users --")
    print(f"Result: Returned {len(results)} rows (includes stolen user credentials)")
