"""
P4_01_WHERE_MULTI_01_MEDIUM: SQL Injection via WHERE Clause with Multiple Conditions
SECURE REFACTORED VERSION — All injection points fixed via parameterized queries.
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

    # SECURITY FIX: Use positional placeholders (?) instead of f-string interpolation.
    # The DB-API layer handles all escaping; user input never touches the query string.
    query = """
        SELECT id, name, price, status, category
        FROM products
        WHERE status = ?
        AND price >= ?
        AND price <= ?
    """
    params: list = [status, min_price, max_price]

    if category != "all":
        # SECURITY FIX: Conditional clause also uses a placeholder, not f-string.
        query += " AND category = ?"
        params.append(category)

    try:
        cursor.execute(query, params)
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

    # SECURITY FIX: Both username and password are passed as bound parameters.
    # An attacker cannot inject SQL via either field (e.g. "admin' --" trick is neutralised).
    query = """
        SELECT id, username, email, role
        FROM users
        WHERE username = ?
        AND password = ?
    """

    try:
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
    Get orders with optional filters.

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

    # SECURITY FIX: Build dynamic query with placeholders only; collect values separately.
    # The query string is constructed from static literals — no user data touches it.
    query = "SELECT * FROM orders WHERE 1=1"
    params: list = []

    if customer_id is not None:
        # SECURITY FIX: Integer placeholder prevents numeric injection.
        query += " AND customer_id = ?"
        params.append(customer_id)

    if start_date:
        # SECURITY FIX: Date string goes into parameter, not into the query text.
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
        results = [dict(row) for row in cursor.fetchall()]
        return results
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []
    finally:
        conn.close()
