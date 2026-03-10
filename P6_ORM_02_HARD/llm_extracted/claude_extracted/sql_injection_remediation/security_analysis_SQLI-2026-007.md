# Security Remediation Report
## Django ORM Multi-Model SQL Injection Vulnerabilities

| Field | Detail |
|---|---|
| **Finding ID** | SQLI-2026-007 |
| **Severity** | 🔴 CRITICAL (CVSS 9.8) |
| **Application** | Project Management System (Django Multi-Model Architecture) |
| **Total Injection Points** | 10+ across 4 models + query builder |
| **Status** | ✅ REMEDIATED — All injection points fixed |
| **Date Identified** | February 10, 2025 |

---

## 1. Executive Summary

A penetration test of the Django-based Project Management System identified multiple critical SQL injection vulnerabilities across four models (User, Project, Task, Comment) and a custom query builder. Attackers exploiting these vulnerabilities could extract all database contents, modify records across all models, escalate privileges, and potentially gain direct database server access.

All 10+ injection points have been fully remediated using a two-pronged approach:

1. **Allowlist validation** for all dynamic SQL identifiers (field names, ORDER BY, GROUP BY, SELECT columns, HAVING expressions)
2. **Parameterized queries / Django ORM** for all user-supplied values
3. **Elimination** of all false-security validator patterns (`validators.py`)

---

## 2. Why the Original Validators Failed

`validators.py` provided a false sense of security. Each validator had fundamental flaws:

| Validator | Claimed Protection | Why It Failed |
|---|---|---|
| `validate_field_name` | Blocks non-alphanumeric chars | Allows `a-z`, `0-9`, underscore — enough for payloads like `status,(SELECT 1)` |
| `sanitize_sql_keywords` | Blocks DROP/DELETE/UPDATE | Only 6 keywords; `SELECT`, `UNION`, `CASE`, `pg_sleep`, `version()` all pass through |
| `validate_length` | Input length cap | A 50-char payload still injects — length has no bearing on SQL semantics |
| `InputValidator.sanitize_quotes` | Escapes single quotes | Not parameterization; bypassable via numeric injection or encoding |
| `validate_sql_expression` | Regex pattern matching | Falls through to `return True` if no pattern matches — explicitly allows everything |

> **Key principle:** Blocklists are fragile. SQL has too many ways to express the same semantics (case variation, comments, encoding, whitespace). Allowlists — used in the fix — are safe by default: anything not explicitly permitted is rejected.

---

## 3. Vulnerability Inventory

| # | Location | Vulnerability Type | Remediation Applied | Post-Fix |
|---|---|---|---|---|
| 1 | `Project.search_by_criteria()` | Dynamic field name in WHERE | `PROJECT_SEARCH_FIELDS` allowlist replaces weak `isalnum()` | ✅ LOW |
| 2a | `Project.get_projects_with_stats()` | ORDER BY f-string injection | `PROJECT_SORT_FIELDS` allowlist + ORM `order_by()` | ✅ LOW |
| 2b | `Project.get_projects_with_stats()` | Free-text WHERE filters | Replaced with ORM `.filter(**dict)` | ✅ LOW |
| 3 | `Task.filter_with_raw_sql()` | Full WHERE clause control | Method refactored to ORM `.filter(**kwargs)` | ✅ LOW |
| 4 | `Task.get_tasks_by_criteria()` | GROUP BY f-string injection | `TASK_GROUP_FIELDS` allowlist | ✅ LOW |
| 5 | `Task.get_tasks_by_criteria()` | Free-text HAVING clause | Replaced with typed `int min_count` + `%s` param | ✅ LOW |
| 6 | `Comment.search_comments()` | SELECT column list injection | `COMMENT_SEARCH_COLUMNS` key-to-col mapping | ✅ LOW |
| 7 | `Comment.get_comments_with_filter()` | ORDER BY expression injection | `COMMENT_ORDER_FIELDS` allowlist | ✅ LOW |
| 8 | `ProjectQueryBuilder.select()` | Accumulated SELECT fields | Allowlist-validated; annotation for `task_count` | ✅ LOW |
| 9 | `ProjectQueryBuilder.where()` | Accumulated WHERE strings | Now accepts `Q()` objects / ORM kwargs only | ✅ LOW |
| 10 | `ProjectQueryBuilder.having_clause()` | Raw HAVING string | Replaced with typed int + ORM annotation filter | ✅ LOW |
| + | `get_user_dashboard_stats()` | f-string `stat_field` + `filter_clause` | `USER_STAT_FIELDS` allowlist + ORM kwargs | ✅ LOW |
| + | `TaskAggregator` | `.extra()` and `RawSQL()` with user input | Removed; replaced with pure ORM | ✅ LOW |

---

## 4. Technical Deep-Dive

### 4.1 The Core Problem: Identifiers Cannot Be Parameterized

Django's (and SQL's) parameterization mechanism — `%s` placeholders — works only for **values**, not for SQL **identifiers** (column names, table names, ORDER BY fields, GROUP BY fields, SELECT expressions). This is a fundamental SQL constraint. The original code used f-strings as a workaround, creating injection vulnerabilities.

```python
# ORIGINAL — VULNERABLE
query = f"SELECT * FROM projects WHERE {search_field} = %s"
# search_field could be: "name UNION SELECT * FROM users --"

# FIX — safe_field is from an explicit allowlist, never from raw user input
ALLOWED = {'name', 'status', 'priority'}
if search_field not in ALLOWED:
    raise ValueError("Invalid field")
query = f"SELECT * FROM projects WHERE {search_field} = %s"
# Now search_field is always exactly 'name', 'status', or 'priority'
```

---

### 4.2 Injection #1 — Dynamic Field Name (`models.py`)

**Location:** `Project.search_by_criteria(search_field, search_value)`

The original validation used `search_field.replace('_', '').isalnum()` — this blocks spaces and special characters but permits payloads like:

```python
# Passes isalnum() check after stripping underscores:
search_field = "name_UNION_SELECT_id_username_FROM_users__"
# Resulting SQL:
# WHERE name UNION SELECT id, username FROM users -- = %s
```

**Fix:** `PROJECT_SEARCH_FIELDS = {'name', 'status', 'priority', 'description'}` — only exact members of this set are accepted.

---

### 4.3 Injection #2b — Free-Text WHERE Filters (`models.py`)

**Location:** `Project.get_projects_with_stats(sort_field, filters)`

```python
# ORIGINAL — attacker supplies raw SQL string
if filters:
    base_query += f" WHERE {filters}"
# Payload: "p.status = 'active' OR 1=1 --"

# FIX — filters is now a dict of ORM kwargs
if filters and isinstance(filters, dict):
    qs = qs.filter(**filters)
# Payload must be {"status": "active"} — Django parameterizes the value
```

---

### 4.4 Injection #3 — Full WHERE Control (`models.py`)

**Location:** `Task.filter_with_raw_sql(filter_expression)`

This was the most dangerous injection point — the **entire WHERE clause** was user-controlled. The fix eliminates the raw SQL approach entirely in favour of typed keyword arguments:

```python
# ORIGINAL — attacker controls entire WHERE clause
query = f"""
    SELECT ... FROM tasks
    WHERE {filter_expression}
"""
# Payload: "1=1 UNION SELECT id, title, 'INJECTED', ... FROM tasks --"

# FIX — ORM handles parameterization; caller passes typed args
@classmethod
def filter_with_raw_sql(cls, status=None, priority=None, assignee_id=None):
    qs = cls.objects.select_related('assignee', 'project')
    if status:      qs = qs.filter(status=status)
    if priority:    qs = qs.filter(priority=priority)
    if assignee_id: qs = qs.filter(assignee_id=assignee_id)
    return list(qs)
```

---

### 4.5 Injections #4 & #5 — GROUP BY and HAVING (`models.py`)

**Location:** `Task.get_tasks_by_criteria(group_by_field, having_clause)`

Two separate injection vectors in the same method. The GROUP BY field had the same weak alphanumeric check as #1. The HAVING clause accepted a free-text SQL expression with **no validation at all**.

```python
# ORIGINAL
query = f"... GROUP BY {group_by_field}"
query += f" HAVING {having_clause}"
# Payload (having): "COUNT(*) > 0 OR 1=1"

# FIX — allowlist for GROUP BY; typed integer for HAVING
TASK_GROUP_FIELDS = {'status', 'priority', 'project_id', 'assignee_id'}
safe_group = _safe_identifier(group_by_field, TASK_GROUP_FIELDS)

query = f"... GROUP BY {safe_group}"
if min_count is not None:
    query += " HAVING COUNT(*) >= %s"
    params.append(int(min_count))  # Typed, parameterized
```

---

### 4.6 Injection #6 — SELECT Column List (`models.py`)

**Location:** `Comment.search_comments(search_columns, search_term)`

The original validation only checked that a keyword like `content` appeared *somewhere* in the string — easily satisfied while still injecting:

```python
# Passes validation (contains "content"), but injects a subquery:
search_columns = "content, (SELECT string_agg(tablename,',') FROM pg_tables)"

# FIX — map a safe key to a hardcoded column reference
COMMENT_SEARCH_COLUMNS = {
    'content':    'c.content',
    'author':     'u.username',
    'task':       't.title',
    'created_at': 'c.created_at',
}
# Only the safe mapped value is ever used in the query
safe_col = COMMENT_SEARCH_COLUMNS[search_column_key]
```

---

### 4.7 Injections #8–#10 — Query Builder Pattern (`query_builder.py`)

The `ProjectQueryBuilder` accumulated raw strings across multiple method calls before executing a combined query. This chained pattern is particularly dangerous because:

- Each `.select()`, `.where()`, and `.having_clause()` call added to a string buffer
- `.build_and_execute()` concatenated all parts into a single raw SQL string
- An attacker could inject across multiple parameters simultaneously

```python
# ORIGINAL — raw string accumulation
self.select_fields.append(field)        # raw SQL string
self.where_conditions.append(condition) # raw SQL string
query = f"SELECT {select_clause} ... WHERE {where_clause}"

# FIX — ORM wrapper, no string accumulation
def where(self, q_object=None, **kwargs):
    if q_object: self._qs = self._qs.filter(q_object)  # Q() only
    if kwargs:   self._qs = self._qs.filter(**kwargs)   # typed kwargs

def build_and_execute(self):
    qs = self._qs
    if self._annotate_task_count:
        qs = qs.annotate(task_count=Count('tasks'))
    if self._min_task_count:
        qs = qs.filter(task_count__gte=self._min_task_count)
    return list(qs.order_by(self._order_field))
```

---

## 5. Files Delivered

| File | Injection Points Fixed | Key Changes |
|---|---|---|
| `models.py` | #1, #2a, #2b, #3, #4, #5, #6, #7 | Allowlists for all dynamic identifiers; HAVING → typed int; `filter_with_raw_sql` refactored to ORM |
| `query_builder.py` | #8, #9, #10, + dashboard | Builder rewritten as ORM wrapper; `.extra()` and `RawSQL()` removed; `USER_STAT_FIELDS` allowlist |
| `views.py` | All (API surface) | All handlers updated to pass typed/structured params; false-security validator imports removed; filters now JSON-decoded dicts |
| `validators.py` | N/A — removed | Entire file superseded; real security now embedded in allowlists in the model/builder layer |

---

## 6. Recommendations & Prevention

### 6.1 Immediate Actions ✅ Done

1. All 10+ injection points remediated with allowlist + parameterization approach
2. `validators.py` false-security layer removed to prevent false confidence
3. API surface (`views.py`) updated to reject free-text SQL parameters

### 6.2 Ongoing Practices

- **Prefer Django ORM** queryset methods over `.raw()` wherever possible — raw SQL should be a last resort
- **Never use `.extra()`** — it is documented as a security risk and is deprecated
- **Code review checklist:** flag any f-string or `%` format used inside a SQL query string
- **Add SAST scanning** (e.g. [Bandit](https://bandit.readthedocs.io/) for Python) to CI/CD to catch raw SQL patterns automatically
- **Principle of least privilege:** the database user for this application should not have DDL permissions (no CREATE, DROP, ALTER)

### 6.3 Allowlists vs Blocklists — the Core Principle

The original `validators.py` relied on **blocklists** (blocking `DROP`, `DELETE`, `UPDATE`). Blocklists are fundamentally fragile for SQL injection because:

- SQL has many ways to express the same semantics (case variation, comments, encoding, whitespace)
- Data-extraction attacks (`SELECT`, `UNION`) were not even blocked
- Every new attack technique requires a blocklist update

**Allowlists** (as implemented in the fix) are safe by default. The surface area to maintain is small and stable — if it's not in the list, it doesn't run.

---

*End of Report — SQLI-2026-007 | Confidential — Internal Use Only*
