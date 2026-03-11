"""
P4_01_WHERE_MULTI_01_MEDIUM: SQL Injection via WHERE Clause with Multiple Conditions
SECURE REFACTORED VERSION - Google Gemini Response
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
    Search products using parameterized queries to prevent SQL Injection.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Define base query with placeholders (?)
    query = """
        SELECT id, name, price, status, category
        FROM products
        WHERE status = ?
        AND price >= ?
        AND price <= ?
    """
    params = [status, min_price, max_price]
    
    if category != "all":
        query += " AND category = ?"
        params.append(category)
    
    try:
        # Input is passed as a separate tuple/list
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []
    finally:
        conn.close()


def authenticate_user(db_path: str, username: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Secure authentication using parameter binding.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    query = """
        SELECT id, username, email, role
        FROM users
        WHERE username = ?
        AND password = ?
    """
    
    try:
        # Prevents 'OR 1=1' attacks
        cursor.execute(query, (username, password))
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
    Secure dynamic query generation.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    query = "SELECT * FROM orders WHERE 1=1"
    params = []
    
    if customer_id is not None:
        query += " AND customer_id = ?"
        params.append(customer_id)
    
    if start_date:
        query += " AND order_date >= ?"
        params.append(start_date)
    
    if end_date:
        query += " AND order_date <= ?"
        params.append(end_date)
    
    if min_total is not None:
        query += " AND total >= ?"
        params.append(min_total)
    
    try:
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []
    finally:
        conn.close()
