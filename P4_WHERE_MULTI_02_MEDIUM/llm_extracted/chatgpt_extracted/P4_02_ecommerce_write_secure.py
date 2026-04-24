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
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    query = "SELECT id, customer_id, order_date, total, status FROM orders WHERE 1=1"
    params = []
    
    if status is not None:
        query += " AND status = ?"
        params.append(status)
    
    if customer_id is not None:
        query += " AND customer_id = ?"
        params.append(customer_id)
    
    if min_total is not None:
        query += " AND total >= ?"
        params.append(min_total)
    
    try:
        cursor.execute(query, params)
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
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    query = """
        INSERT INTO products (name, price, category, status)
        VALUES (?, ?, ?, ?)
    """
    
    try:
        cursor.execute(query, (name, price, category, status))
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
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    query = """
        UPDATE orders
        SET status = ?
        WHERE id = ?
        AND customer_id = ?
    """
    
    try:
        cursor.execute(query, (new_status, order_id, customer_id))
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
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    query = """
        DELETE FROM products
        WHERE category = ?
        AND status = ?
    """
    
    try:
        cursor.execute(query, (category, status_threshold))
        conn.commit()
        deleted_count = cursor.rowcount
        return deleted_count
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return 0
    finally:
        conn.close()


def init_ecommerce_database(db_path: str) -> bool:
    try:
        if sqlite3.connect(db_path):
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS products (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    price REAL NOT NULL,
                    category TEXT NOT NULL,
                    status TEXT NOT NULL
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    email TEXT NOT NULL,
                    role TEXT NOT NULL
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS orders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    customer_id INTEGER NOT NULL,
                    order_date TEXT NOT NULL,
                    total REAL NOT NULL,
                    status TEXT NOT NULL
                )
            """)
            
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
            return True
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}")
        return False