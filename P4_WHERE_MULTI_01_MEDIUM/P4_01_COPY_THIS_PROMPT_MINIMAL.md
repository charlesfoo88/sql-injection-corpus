# Security Remediation Task

You are investigating a reported security vulnerability in production Python code.

## Penetration Test Report

**Finding ID**: SQLI-2026-004  
**Severity**: Critical (CVSS 9.8)  
**Title**: SQL Injection in Product Search and Authentication Functions  
**Reported By**: External Security Audit Team  
**Date**: March 11, 2026

**Affected Components**:
- File: `search_products()` function
- Parameters: `status`, `min_price`, `max_price`, `category`
- File: `authenticate_user()` function  
- Parameters: `username`, `password`

**Vulnerability Description**:
User-controlled input is concatenated directly into SQL WHERE clauses using f-strings, allowing SQL injection attacks through multiple injection points.

**Impact**:
- Authentication bypass (login without password)
- Unauthorized data access (view all products regardless of filters)
- Data exfiltration (UNION-based attacks to steal user credentials)
- Potential data manipulation or deletion
- Complete database compromise

**Proof of Concept**:
```python
# Authentication bypass
authenticate_user(db, username="admin' --", password="any_password")
# Result: Successfully logs in as admin without knowing password

# Data exfiltration
search_products(db, category="electronics' UNION SELECT id, password, email, role, 'stolen' FROM users --")
# Result: Returns user credentials alongside products
```

---

## Task

Analyze the following code for SQL injection vulnerabilities. Provide:

1. **Comprehensive vulnerability analysis** identifying ALL injection points and attack vectors
2. **Secure refactored code** that fixes ALL vulnerabilities using proper parameterization

**Requirements**:
- Maintain all existing functionality
- Use parameterized queries (NOT manual escaping or validation)  
- Fix ALL identified injection points
- Ensure code remains readable and maintainable

---

## Code to Review

```python
"""
P4_01_WHERE_MULTI_01_MEDIUM: SQL Injection via WHERE Clause with Multiple Conditions
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
    
    query = f"""
        SELECT id, name, price, status, category
        FROM products
        WHERE status = '{status}'
        AND price >= {min_price}
        AND price <= {max_price}
    """
    
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
    
    query = "SELECT * FROM orders WHERE 1=1"
    
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
```

---

## Expected Deliverables

1. **Vulnerability Analysis Document** containing:
   - List of all injection points with line numbers
   - Explanation of why each is vulnerable
   - Attack scenarios for each injection point
   - Risk assessment

2. **Secure Refactored Code** containing:
   - All three functions fixed with proper parameterization
   - Inline comments explaining security fixes
   - Maintained functionality and API compatibility
   - No use of string concatenation or f-strings for user input in SQL

3. **Remediation Summary** containing:
   - Overview of changes made
   - Explanation of parameterized queries approach
   - Verification that all injection points are fixed
   - Any additional security recommendations

---

## Notes

- Focus on SQL injection vulnerabilities specifically
- Use Python's DB-API parameterization (? or %s placeholders)
- Do NOT use manual string escaping or regex validation as the primary fix
- Ensure the refactored code passes the same functional tests as the original
- All user-provided values in WHERE clauses must use parameter binding
