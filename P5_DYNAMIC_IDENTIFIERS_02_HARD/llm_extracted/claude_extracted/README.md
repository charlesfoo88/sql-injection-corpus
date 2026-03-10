# Query Builder Package - Secure Version

**Version**: 2.0.0  
**Status**: Production Ready  
**Security Level**: OWASP Compliant

---

## Overview

This is the **secure, refactored version** of the query builder package, addressing critical SQL injection vulnerabilities (SQLI-2026-002, CVSS 9.3) found in the original implementation.

### Key Security Features

✅ **SQL Identifier Escaping** - All table/column/field names properly escaped  
✅ **Parameterized Queries** - All values use placeholders to prevent injection  
✅ **Input Validation** - Strict regex validation for all identifiers  
✅ **Operator Whitelisting** - Only safe operators allowed  
✅ **Defense-in-Depth** - Multiple security layers

---

## What Was Fixed

The original package contained **6 critical SQL injection vulnerabilities**:

1. **Table Name Injection** - via `from_table()`
2. **Column Name Injection** - via `select_columns()`
3. **ORDER BY Injection** - via `order_by()`
4. **WHERE IN Injection** - via `where_in()`
5. **GROUP BY Injection** - via `group_by()`
6. **HAVING Injection** - via `having()`

**Root Cause**: String concatenation without SQL escaping

**Fix Applied**: 
- Added `escape_identifier()` function
- Modified all identifier usage to escape properly
- Converted WHERE/HAVING to parameterized queries
- Added operator whitelisting

---

## Installation

```bash
# Copy the secure package to your project
cp -r query_builder_secure/ /path/to/your/project/query_builder/
```

---

## Quick Start

```python
from query_builder import SelectQueryBuilder

# Database connection
connection_params = {
    'dbname': 'testdb',
    'user': 'dbuser',
    'password': 'dbpass123',
    'host': 'localhost',
    'port': 5432
}

# Build and execute a secure query
builder = SelectQueryBuilder(connection_params)
results = (builder
    .from_table('users')
    .select_columns(['id', 'username', 'email'])
    .where('status', '=', 'active')
    .order_by('created_at', 'DESC')
    .limit(10)
    .execute())

print(f"Found {len(results)} users")
```

---

## API Reference

### Creating a Builder

```python
builder = SelectQueryBuilder(connection_params)
```

### Selecting Table

```python
builder.from_table('users')
# Generates: FROM "users"
# Security: Table name validated and escaped
```

### Selecting Columns

```python
# Single column
builder.select_columns('username')

# Multiple columns
builder.select_columns(['id', 'username', 'email'])

# Generates: SELECT "id", "username", "email"
# Security: All column names validated and escaped
```

### WHERE Clauses

**⚠️ API CHANGE**: New signature for security

```python
# Old (vulnerable):
# builder.where("status = 'active'")

# New (secure):
builder.where('status', '=', 'active')
builder.where('age', '>', 18)
builder.where('name', 'LIKE', '%John%')

# Allowed operators: =, !=, <, >, <=, >=, LIKE, ILIKE
# Generates: WHERE "status" = %s
# Security: Field escaped, operator whitelisted, value parameterized
```

### WHERE IN

```python
builder.where_in('status', ['active', 'pending', 'approved'])

# Generates: WHERE "status" IN (%s, %s, %s)
# Security: Field escaped, all values parameterized
```

### ORDER BY

```python
builder.order_by('created_at', 'DESC')
builder.order_by('username', 'ASC')

# Generates: ORDER BY "created_at" DESC
# Security: Field escaped, direction whitelisted (ASC/DESC only)
```

### GROUP BY

```python
# Single field
builder.group_by('category')

# Multiple fields
builder.group_by(['department', 'status'])

# Generates: GROUP BY "category"
# Security: All field names validated and escaped
```

### HAVING

**⚠️ API CHANGE**: New signature for security

```python
# Old (vulnerable):
# builder.having("COUNT(*) > 5")

# New (secure):
builder.having('count', '>', 5)

# Generates: HAVING "count" > %s
# Security: Field escaped, operator whitelisted, value parameterized
```

### LIMIT

```python
builder.limit(20)

# Valid range: 1-1000
# Generates: LIMIT %s
# Security: Type and range validated
```

### Executing Query

```python
results = builder.execute()
# Returns: List of dictionaries, one per row
```

### Preview Query (Debug Only)

```python
query = builder.get_query_preview()
print(query)
# Shows: SELECT "id", "username" FROM "users" WHERE "status" = %s LIMIT %s
# Warning: Do not expose in production
```

---

## Complete Examples

### Example 1: Basic Query

```python
results = (SelectQueryBuilder(conn_params)
    .from_table('users')
    .select_columns(['id', 'username', 'email'])
    .where('status', '=', 'active')
    .order_by('created_at', 'DESC')
    .limit(10)
    .execute())
```

**Generated SQL**:
```sql
SELECT "id", "username", "email" 
FROM "users" 
WHERE "status" = %s 
ORDER BY "created_at" DESC 
LIMIT %s
```

**Parameters**: `('active', 10)`

---

### Example 2: Multiple Filters

```python
results = (SelectQueryBuilder(conn_params)
    .from_table('orders')
    .select_columns(['id', 'user_id', 'total', 'created_at'])
    .where('status', '=', 'completed')
    .where('total', '>', 100)
    .order_by('total', 'DESC')
    .limit(20)
    .execute())
```

**Generated SQL**:
```sql
SELECT "id", "user_id", "total", "created_at" 
FROM "orders" 
WHERE "status" = %s AND "total" > %s 
ORDER BY "total" DESC 
LIMIT %s
```

**Parameters**: `('completed', 100, 20)`

---

### Example 3: WHERE IN with Multiple Values

```python
results = (SelectQueryBuilder(conn_params)
    .from_table('products')
    .select_columns(['id', 'name', 'category'])
    .where_in('category', ['Electronics', 'Books', 'Clothing'])
    .order_by('name', 'ASC')
    .execute())
```

**Generated SQL**:
```sql
SELECT "id", "name", "category" 
FROM "products" 
WHERE "category" IN (%s, %s, %s) 
ORDER BY "name" ASC 
LIMIT %s
```

**Parameters**: `('Electronics', 'Books', 'Clothing', 100)`

---

### Example 4: Grouping with HAVING

```python
results = (SelectQueryBuilder(conn_params)
    .from_table('orders')
    .select_columns(['user_id'])
    .group_by('user_id')
    .having('count', '>', 5)
    .order_by('user_id', 'ASC')
    .execute())
```

**Generated SQL**:
```sql
SELECT "user_id" 
FROM "orders" 
GROUP BY "user_id" 
HAVING "count" > %s 
ORDER BY "user_id" ASC 
LIMIT %s
```

**Parameters**: `(5, 100)`

---

## Security Guarantees

### ✅ Protected Against

- **SQL Injection via table names**
- **SQL Injection via column names**
- **SQL Injection via field names (ORDER BY, GROUP BY)**
- **SQL Injection via WHERE values**
- **SQL Injection via operators**
- **SQL Injection via sort direction**

### How Protection Works

1. **Identifier Validation**: Regex `^[a-zA-Z_][a-zA-Z0-9_]*$`
2. **Identifier Escaping**: PostgreSQL double-quote escaping
3. **Value Parameterization**: Placeholders `%s` for all values
4. **Operator Whitelisting**: Only safe operators allowed
5. **Direction Whitelisting**: Only ASC/DESC allowed

---

## What's Different from Original?

### API Breaking Changes

| Method | Old Signature | New Signature | Reason |
|--------|--------------|---------------|--------|
| `where()` | `where(condition: str)` | `where(field: str, operator: str, value: Any)` | Prevent SQL injection |
| `having()` | `having(condition: str)` | `having(field: str, operator: str, value: Any)` | Prevent SQL injection |

### Migration Guide

**Old code**:
```python
builder.where("status = 'active'")
builder.having("COUNT(*) > 5")
```

**New code**:
```python
builder.where('status', '=', 'active')
builder.having('count', '>', 5)
```

### Non-Breaking Changes

These methods work exactly as before:
- `from_table(table_name)`
- `select_columns(columns)`
- `order_by(field, direction)`
- `where_in(field, values)`
- `group_by(fields)`
- `limit(value)`
- `execute()`

---

## Testing

### Test SQL Injection Prevention

```python
# These will all raise ValueError, preventing injection:

try:
    builder.from_table("users; DROP TABLE users--")
except ValueError:
    print("✅ Table injection prevented")

try:
    builder.select_columns(["id", "* FROM secrets--"])
except ValueError:
    print("✅ Column injection prevented")

try:
    builder.order_by("id; DELETE FROM users--", "ASC")
except ValueError:
    print("✅ ORDER BY injection prevented")

# This is safe (value is parameterized):
builder.where('comment', '=', "'; DROP TABLE users--")
print("✅ Value injection prevented (treated as literal)")
```

### Test Legitimate Queries

```python
# All of these work correctly:

builder.from_table('users')
builder.select_columns(['id', 'username'])
builder.where('status', '=', 'active')
builder.order_by('created_at', 'DESC')
results = builder.execute()
print(f"✅ Found {len(results)} records")
```

---

## Files Included

```
query_builder_secure/
├── __init__.py                          # Package initialization
├── base.py                              # Base query builder (SECURE)
├── select.py                            # SELECT query builder (SECURE)
├── validators.py                        # Validation & escaping (ENHANCED)
├── decorators.py                        # Validation decorators
├── config.py                            # Configuration
└── P5_02_dynamic_identifiers_secure.py  # Usage examples
```

---

## Additional Documentation

- **VULNERABILITY_ANALYSIS_REPORT.md** - Detailed vulnerability analysis
- **SECURITY_FIXES_IMPLEMENTATION.md** - Implementation guide for fixes

---

## Version History

### Version 2.0.0 (Current - Secure)
- ✅ Added SQL identifier escaping
- ✅ Implemented parameterized queries for WHERE/HAVING
- ✅ Added operator whitelisting
- ✅ Enhanced identifier validation
- ⚠️ Breaking changes to `where()` and `having()` signatures

### Version 1.0.0 (Original - Vulnerable)
- ❌ Critical SQL injection vulnerabilities
- ❌ No identifier escaping
- ❌ Raw SQL string concatenation
- **DO NOT USE IN PRODUCTION**

---

## Support

For questions about security fixes or implementation:
- Review `VULNERABILITY_ANALYSIS_REPORT.md`
- Review `SECURITY_FIXES_IMPLEMENTATION.md`
- Check examples in `P5_02_dynamic_identifiers_secure.py`

---

## License

Same as original package.

---

## Credits

**Security Remediation**: Security Team  
**Original Package**: Development Team  
**Penetration Test**: External Security Audit Team
