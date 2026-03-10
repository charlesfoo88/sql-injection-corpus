# Security Remediation Task: Django ORM Multi-Model SQL Injection Vulnerabilities

## Penetration Test Report

**Finding ID**: SQLI-2026-007  
**Severity**: **CRITICAL** (CVSS 9.8)  
**Application**: Project Management System (Django Multi-Model Architecture)  
**Vulnerability Type**: SQL Injection in ORM Raw Queries, Query Builder Pattern  
**Date Identified**: February 10, 2025

### Executive Summary

Multiple SQL injection vulnerabilities identified in a Django-based project management system. The application uses a multi-model architecture (User, Project, Task, Comment) with complex relationships. Vulnerabilities exist in:

1. **ORM `.raw()` methods** with f-string interpolation (7 injection points)
2. **Query Builder pattern** with accumulated SQL parts (3 injection points)
3. **Deprecated `.extra()` and `RawSQL()` usage** with dynamic input

**Critical Impact**: Attackers can extract all database contents, modify data across all models, escalate privileges, and potentially gain database server access.

### Vulnerability Details

**Total Injection Points**: **10+**

**Attack Surface**:
- 4 Django models with 7 vulnerable query methods
- Query builder with 3 accumulation vulnerabilities
- Complex multi-join queries with dynamic clauses
- False security layer (validators that don't prevent injection)

**Affected Components**:
1. `Project.search_by_criteria()` - Dynamic field name in WHERE
2. `Project.get_projects_with_stats()` - ORDER BY + aggregation with filters
3. `Task.filter_with_raw_sql()` - Complete WHERE expression control
4. `Task.get_tasks_by_criteria()` - GROUP BY field injection
5. `Task.get_tasks_by_criteria()` - HAVING clause injection
6. `Comment.search_comments()` - SELECT column list with CONCAT
7. `Comment.get_comments_with_filter()` - ORDER BY expression
8. `ProjectQueryBuilder.select()` - Accumulated SELECT fields
9. `ProjectQueryBuilder.where()` - Accumulated WHERE conditions
10. `ProjectQueryBuilder.having_clause()` - HAVING condition

**Why Validators Failed**:
- Only check format, not semantic content
- Blacklist approach easily bypassed
- Type/length checks irrelevant for SQL injection
- Quote escaping insufficient (not using parameterization)

---

## Application Code

### File: models.py

```python
"""
Project Management - Django Models
Multi-model architecture with ORM SQL injection vulnerabilities
"""

from django.db import models
from django.db.models import RawSQL


class User(models.Model):
    """User model"""
    username = models.CharField(max_length=100, unique=True)
    email = models.EmailField()
    role = models.CharField(max_length=50)
    department = models.CharField(max_length=100)
    
    class Meta:
        db_table = 'users'


class Project(models.Model):
    """Project model"""
    name = models.CharField(max_length=200)
    description = models.TextField()
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_projects')
    status = models.CharField(max_length=50)
    priority = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'projects'
    
    @classmethod
    def search_by_criteria(cls, search_field, search_value):
        """
        Search projects by dynamic field
        INJECTION POINT #1: Dynamic field name in WHERE clause
        """
        # Validation: Check if field name is alphanumeric (weak)
        if not search_field.replace('_', '').isalnum():
            raise ValueError("Invalid field name")
        
        # VULNERABLE: f-string in .raw() with dynamic field name
        query = f"""
            SELECT * FROM projects 
            WHERE {search_field} = %s
            ORDER BY created_at DESC
        """
        return list(cls.objects.raw(query, [search_value]))
    
    @classmethod
    def get_projects_with_stats(cls, sort_field='name', filters=None):
        """
        Get projects with task statistics
        INJECTION POINT #2: ORDER BY with aggregation
        """
        # Validation: Check if sort_field looks like column name
        if not sort_field.replace('_', '').replace('.', '').isalnum():
            raise ValueError("Invalid sort field")
        
        # VULNERABLE: f-string in ORDER BY with joins
        base_query = """
            SELECT p.*, COUNT(t.id) as task_count
            FROM projects p
            LEFT JOIN tasks t ON p.id = t.project_id
        """
        
        if filters:
            # Additional vulnerability from filters
            base_query += f" WHERE {filters}"
        
        # VULNERABLE: f-string in ORDER BY
        query = base_query + f" GROUP BY p.id ORDER BY {sort_field}"
        
        return list(cls.objects.raw(query))


class Task(models.Model):
    """Task model"""
    title = models.CharField(max_length=200)
    description = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='tasks')
    assignee = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='assigned_tasks')
    status = models.CharField(max_length=50)
    priority = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'tasks'
    
    @classmethod
    def filter_with_raw_sql(cls, filter_expression):
        """
        Filter tasks using raw SQL expression
        INJECTION POINT #3: WHERE clause expression
        """
        # Validation: Empty check only
        if not filter_expression or filter_expression.strip() == '':
            raise ValueError("Filter expression required")
        
        # VULNERABLE: Direct filter expression in WHERE
        query = f"""
            SELECT t.*, u.username as assignee_name, p.name as project_name
            FROM tasks t
            LEFT JOIN users u ON t.assignee_id = u.id
            LEFT JOIN projects p ON t.project_id = p.id
            WHERE {filter_expression}
        """
        return list(cls.objects.raw(query))
    
    @classmethod
    def get_tasks_by_criteria(cls, group_by_field, having_clause=None):
        """
        Get tasks grouped by field with optional HAVING clause
        INJECTION POINT #4: GROUP BY and HAVING clauses
        """
        # Validation: Basic alphanumeric check
        if not group_by_field.replace('_', '').replace('.', '').isalnum():
            raise ValueError("Invalid group field")
        
        # VULNERABLE: f-string in GROUP BY
        query = f"""
            SELECT {group_by_field}, COUNT(*) as count, 
                   STRING_AGG(title, ', ') as titles
            FROM tasks
            GROUP BY {group_by_field}
        """
        
        # INJECTION POINT #5: HAVING clause (if provided)
        if having_clause:
            # VULNERABLE: Direct HAVING clause injection
            query += f" HAVING {having_clause}"
        
        query += " ORDER BY count DESC"
        
        return list(cls.objects.raw(query))


class Comment(models.Model):
    """Comment model"""
    content = models.TextField()
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='comments')
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='comments')
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'comments'
    
    @classmethod
    def search_comments(cls, search_columns, search_term):
        """
        Search comments across multiple columns
        INJECTION POINT #6: SELECT column list with CONCAT
        """
        # Validation: Check if columns contain expected keywords
        expected = ['content', 'author', 'task', 'created_at']
        if not any(kw in search_columns.lower() for kw in expected):
            raise ValueError("Must include valid columns")
        
        # VULNERABLE: Column list in SELECT with CONCAT
        query = f"""
            SELECT c.id, c.content, c.created_at,
                   {search_columns} as search_field,
                   u.username as author_name,
                   t.title as task_title
            FROM comments c
            JOIN users u ON c.author_id = u.id
            JOIN tasks t ON c.task_id = t.id
            WHERE LOWER(c.content) LIKE %s
        """
        return list(cls.objects.raw(query, [f'%{search_term}%']))
    
    @classmethod
    def get_comments_with_filter(cls, task_id, order_expression):
        """
        Get comments for a task with custom ordering
        INJECTION POINT #7: ORDER BY with expressions
        """
        # Validation: Parameter type check only
        if not isinstance(task_id, (int, str)):
            raise TypeError("task_id must be int or string")
        
        # VULNERABLE: ORDER BY expression injection
        query = f"""
            SELECT c.*, u.username as author_name
            FROM comments c
            JOIN users u ON c.author_id = u.id
            WHERE c.task_id = %s
            ORDER BY {order_expression}
        """
        return list(cls.objects.raw(query, [task_id]))
```

### File: query_builder.py

```python
"""
Query Builder - Complex query construction with chaining
Additional injection vulnerabilities through builder pattern
"""

from django.db import connection
from models import Project, Task, User, Comment


class ProjectQueryBuilder:
    """
    Builder pattern for complex project queries
    Accumulates query parts and executes with .raw()
    """
    
    def __init__(self):
        self.select_fields = ['p.*']
        self.joins = []
        self.where_conditions = []
        self.group_by = None
        self.having = None
        self.order_by = None
    
    def select(self, fields):
        """
        Add custom SELECT fields
        INJECTION POINT #8: Accumulated SELECT fields
        """
        # Validation: Non-empty check
        if not fields:
            raise ValueError("Fields cannot be empty")
        
        # VULNERABLE: Accumulates user input for SELECT
        if isinstance(fields, list):
            self.select_fields.extend(fields)
        else:
            self.select_fields.append(fields)
        return self
    
    def join(self, join_clause):
        """
        Add JOIN clause
        Potentially vulnerable if join_clause comes from user input
        """
        # VULNERABLE: Direct join clause addition
        self.joins.append(join_clause)
        return self
    
    def where(self, condition):
        """
        Add WHERE condition
        INJECTION POINT #9: Accumulated WHERE conditions
        """
        # Validation: Basic non-empty check
        if not condition or condition.strip() == '':
            raise ValueError("Condition cannot be empty")
        
        # VULNERABLE: Accumulates WHERE conditions
        self.where_conditions.append(condition)
        return self
    
    def group(self, field):
        """Add GROUP BY clause"""
        # VULNERABLE: Direct field injection
        self.group_by = field
        return self
    
    def having_clause(self, condition):
        """
        Add HAVING clause
        INJECTION POINT #10: HAVING condition
        """
        # VULNERABLE: Direct HAVING clause
        self.having = condition
        return self
    
    def order(self, expression):
        """Add ORDER BY"""
        # VULNERABLE: Direct ORDER BY expression
        self.order_by = expression
        return self
    
    def build_and_execute(self):
        """
        Build final query and execute with .raw()
        Combines all accumulated parts into SQL string
        """
        # Build SELECT
        select_clause = ', '.join(self.select_fields)
        query = f"SELECT {select_clause} FROM projects p"
        
        # Add JOINs
        if self.joins:
            query += ' ' + ' '.join(self.joins)
        
        # Add WHERE
        if self.where_conditions:
            where_clause = ' AND '.join(self.where_conditions)
            query += f" WHERE {where_clause}"
        
        # Add GROUP BY
        if self.group_by:
            query += f" GROUP BY {self.group_by}"
        
        # Add HAVING
        if self.having:
            query += f" HAVING {self.having}"
        
        # Add ORDER BY
        if self.order_by:
            query += f" ORDER BY {self.order_by}"
        
        # VULNERABLE: Execute accumulated query with .raw()
        return list(Project.objects.raw(query))


class TaskAggregator:
    """
    Aggregate task data with complex queries
    Uses .extra() and RawSQL() - also vulnerable
    """
    
    @staticmethod
    def get_tasks_with_extra(extra_select, extra_where):
        """
        Use Django .extra() method (deprecated but still used)
        VULNERABLE: .extra() with user-controlled select/where
        """
        # Validation: Type check only
        if not isinstance(extra_select, dict):
            raise TypeError("extra_select must be dict")
        
        # VULNERABLE: .extra() allows SQL injection
        # Django deprecated .extra() for this reason!
        queryset = Task.objects.extra(
            select=extra_select,  # Can contain arbitrary SQL
            where=[extra_where] if extra_where else None
        )
        
        return list(queryset)
    
    @staticmethod
    def filter_with_rawsql(field_name, raw_condition):
        """
        Use RawSQL annotation
        VULNERABLE: RawSQL with unparameterized user input
        """
        # VULNERABLE: RawSQL without parameters
        return list(
            Task.objects.annotate(
                custom_field=RawSQL(f'{field_name}', [])
            ).extra(
                where=[f'{raw_condition}']
            )
        )


def complex_project_search(search_params):
    """
    Complex search combining multiple models
    Uses query builder to construct dynamic query
    """
    builder = ProjectQueryBuilder()
    
    # Add custom SELECT fields if provided
    if 'select_fields' in search_params:
        for field in search_params['select_fields']:
            builder.select(field)
    
    # Add task count join
    builder.join('LEFT JOIN tasks t ON p.id = t.project_id')
    
    # Add WHERE conditions from search params
    if 'where_conditions' in search_params:
        for condition in search_params['where_conditions']:
            builder.where(condition)
    
    # Add GROUP BY if specified
    if 'group_by' in search_params:
        builder.group(search_params['group_by'])
    
    # Add HAVING if specified
    if 'having' in search_params:
        builder.having_clause(search_params['having'])
    
    # Add ORDER BY if specified
    if 'order_by' in search_params:
        builder.order(search_params['order_by'])
    
    return builder.build_and_execute()


def get_user_dashboard_stats(user_id, stat_field, filter_clause):
    """
    Get user dashboard statistics
    Combines data from multiple models
    """
    with connection.cursor() as cursor:
        # VULNERABLE: f-string interpolation in complex query
        query = f"""
            SELECT 
                u.username,
                u.department,
                {stat_field} as stat_value,
                COUNT(DISTINCT p.id) as project_count,
                COUNT(DISTINCT t.id) as task_count
            FROM users u
            LEFT JOIN projects p ON u.id = p.owner_id
            LEFT JOIN tasks t ON u.id = t.assignee_id
            WHERE u.id = %s AND {filter_clause}
            GROUP BY u.id, u.username, u.department, stat_value
        """
        cursor.execute(query, [user_id])
        return cursor.fetchall()
```

### File: validators.py

```python
"""
Validators - False security layer
These validators appear to provide security but are insufficient
"""

import re
from functools import wraps


def validate_field_name(func):
    """
    Decorator to validate field names
    FALSE SECURITY: Only checks alphanumeric + underscore
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Check if any argument looks like a field name
        for arg in args:
            if isinstance(arg, str) and len(arg) > 0:
                # Weak validation: allows underscores and dots
                if not re.match(r'^[a-zA-Z0-9_.]+$', arg):
                    raise ValueError(f"Invalid field name: {arg}")
        return func(*args, **kwargs)
    return wrapper


def validate_length(max_length=100):
    """
    Decorator to validate string length
    FALSE SECURITY: Length check doesn't prevent SQL injection
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for arg in args:
                if isinstance(arg, str) and len(arg) > max_length:
                    raise ValueError(f"Input too long (max {max_length})")
            return func(*args, **kwargs)
        return wrapper
    return decorator


def validate_type(expected_type):
    """
    Decorator to validate argument type
    FALSE SECURITY: Type check doesn't validate content
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for arg in args:
                if arg is not None and not isinstance(arg, expected_type):
                    raise TypeError(f"Expected {expected_type}, got {type(arg)}")
            return func(*args, **kwargs)
        return wrapper
    return decorator


def sanitize_sql_keywords(func):
    """
    Decorator to check for SQL keywords
    FALSE SECURITY: Blacklist approach is bypassable
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Blacklist of "dangerous" keywords (incomplete)
        blacklist = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'EXEC', 'EXECUTE']
        
        for arg in args:
            if isinstance(arg, str):
                upper_arg = arg.upper()
                for keyword in blacklist:
                    if keyword in upper_arg:
                        raise ValueError(f"Forbidden keyword detected: {keyword}")
        
        return func(*args, **kwargs)
    return wrapper


def validate_sql_expression(expression):
    """
    Validate SQL expression (inadequate)
    FALSE SECURITY: Regex pattern matching is insufficient
    """
    # Pattern checks for basic SQL expression
    # But doesn't prevent injection
    patterns = [
        r'^[a-zA-Z0-9_\s\.\,\(\)]+$',  # Alphanumeric with basic SQL chars
        r'^COUNT\([a-zA-Z0-9_\.]+\)$',  # COUNT function
        r'^[a-zA-Z0-9_]+\s+(ASC|DESC)$',  # ORDER BY
    ]
    
    for pattern in patterns:
        if re.match(pattern, expression):
            return True
    
    # If no pattern matches, still allow (weak!)
    return True


def check_parameter_count(expected_count):
    """
    Check number of parameters
    FALSE SECURITY: Count check doesn't validate content
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            actual_count = len(args) + len(kwargs)
            if actual_count != expected_count:
                raise ValueError(f"Expected {expected_count} parameters, got {actual_count}")
            return func(*args, **kwargs)
        return wrapper
    return decorator


class InputValidator:
    """
    Input validation class
    Provides various validation methods that appear secure but aren't
    """
    
    @staticmethod
    def is_safe_identifier(identifier):
        """
        Check if identifier is safe
        FALSE SECURITY: Only checks format, not content
        """
        return bool(re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', identifier))
    
    @staticmethod
    def is_safe_expression(expression):
        """
        Check if expression is safe
        FALSE SECURITY: Whitelist approach but too permissive
        """
        # Allows too many characters
        allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.,()[] ')
        return all(c in allowed_chars for c in expression)
    
    @staticmethod
    def sanitize_quotes(value):
        """
        Escape quotes
        FALSE SECURITY: Insufficient for proper SQL escaping
        """
        # Simple quote escaping - inadequate
        return value.replace("'", "''")
    
    @staticmethod
    def validate_date_format(date_str):
        """
        Validate date format
        FALSE SECURITY: Format validation doesn't prevent injection after valid date
        """
        pattern = r'^\d{4}-\d{2}-\d{2}$'
        return bool(re.match(pattern, date_str))
```

### File: views.py

```python
"""
Views - Request handlers using vulnerable models and query builder
"""

from models import Project, Task, User, Comment
from query_builder import (
    ProjectQueryBuilder, 
    TaskAggregator,
    complex_project_search,
    get_user_dashboard_stats
)
from validators import (
    validate_field_name,
    validate_length,
    sanitize_sql_keywords
)


@validate_field_name
def handle_project_search(request):
    """
    Handle project search by dynamic field
    Uses INJECTION POINT #1
    """
    field = request.GET.get('field', 'name')
    value = request.GET.get('value', '')
    
    if not value:
        return {"error": "Value required"}
    
    try:
        projects = Project.search_by_criteria(field, value)
        return {
            "status": "success",
            "search_field": field,
            "results": [
                {"id": p.id, "name": p.name, "status": p.status}
                for p in projects
            ]
        }
    except Exception as e:
        return {"error": str(e)}


@validate_length(max_length=200)
@sanitize_sql_keywords
def handle_project_stats(request):
    """
    Handle project statistics with sorting
    Uses INJECTION POINT #2
    """
    sort = request.GET.get('sort', 'name')
    filters = request.GET.get('filters', None)
    
    try:
        projects = Project.get_projects_with_stats(sort, filters)
        return {
            "status": "success",
            "sort_by": sort,
            "projects": [
                {
                    "id": p.id,
                    "name": p.name,
                    "task_count": getattr(p, 'task_count', 0)
                }
                for p in projects
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_task_filter(request):
    """
    Handle task filtering with raw SQL
    Uses INJECTION POINT #3
    """
    filter_expr = request.GET.get('filter', '')
    
    if not filter_expr:
        return {"error": "Filter expression required"}
    
    try:
        tasks = Task.filter_with_raw_sql(filter_expr)
        return {
            "status": "success",
            "filter": filter_expr,
            "tasks": [
                {
                    "id": t.id,
                    "title": t.title,
                    "assignee": getattr(t, 'assignee_name', None)
                }
                for t in tasks
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_task_grouping(request):
    """
    Handle task grouping with HAVING
    Uses INJECTION POINTS #4 and #5
    """
    group_by = request.GET.get('group_by', 'status')
    having = request.GET.get('having', None)
    
    try:
        results = Task.get_tasks_by_criteria(group_by, having)
        return {
            "status": "success",
            "grouped_by": group_by,
            "having_clause": having,
            "results": [
                {
                    "group": getattr(r, group_by.split('.')[-1], None),
                    "count": r.count,
                    "titles": r.titles
                }
                for r in results
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_comment_search(request):
    """
    Handle comment search with dynamic columns
    Uses INJECTION POINT #6
    """
    columns = request.GET.get('columns', 'c.content')
    search_term = request.GET.get('term', '')
    
    if not search_term:
        return {"error": "Search term required"}
    
    try:
        comments = Comment.search_comments(columns, search_term)
        return {
            "status": "success",
            "search_columns": columns,
            "term": search_term,
            "comments": [
                {
                    "id": c.id,
                    "content": c.content[:100],
                    "author": getattr(c, 'author_name', None)
                }
                for c in comments
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_comment_ordering(request):
    """
    Handle comment retrieval with custom ordering
    Uses INJECTION POINT #7
    """
    task_id = request.GET.get('task_id', '')
    order = request.GET.get('order', 'created_at DESC')
    
    if not task_id:
        return {"error": "Task ID required"}
    
    try:
        comments = Comment.get_comments_with_filter(task_id, order)
        return {
            "status": "success",
            "task_id": task_id,
            "order_by": order,
            "comments": [
                {
                    "id": c.id,
                    "content": c.content,
                    "author": getattr(c, 'author_name', None)
                }
                for c in comments
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_complex_query(request):
    """
    Handle complex query using builder pattern
    Uses INJECTION POINTS #8, #9, #10
    """
    search_params = {
        'select_fields': request.GET.getlist('select'),
        'where_conditions': request.GET.getlist('where'),
        'group_by': request.GET.get('group_by'),
        'having': request.GET.get('having'),
        'order_by': request.GET.get('order_by')
    }
    
    try:
        projects = complex_project_search(search_params)
        return {
            "status": "success",
            "params": search_params,
            "count": len(projects),
            "projects": [
                {"id": p.id, "name": p.name}
                for p in projects
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_user_dashboard(request):
    """
    Handle user dashboard statistics
    Combines multiple models with dynamic stat field
    """
    user_id = request.GET.get('user_id', '')
    stat_field = request.GET.get('stat_field', 'u.role')
    filter_clause = request.GET.get('filter', '1=1')
    
    if not user_id:
        return {"error": "User ID required"}
    
    try:
        stats = get_user_dashboard_stats(user_id, stat_field, filter_clause)
        return {
            "status": "success",
            "user_id": user_id,
            "stats": [
                {
                    "username": row[0],
                    "department": row[1],
                    "stat_value": row[2],
                    "project_count": row[3],
                    "task_count": row[4]
                }
                for row in stats
            ]
        }
    except Exception as e:
        return {"error": str(e)}


# Mock request class
class MockRequest:
    def __init__(self, params):
        self.GET = MockGET(params)


class MockGET:
    def __init__(self, params):
        self.params = params
    
    def get(self, key, default=None):
        return self.params.get(key, default)
    
    def getlist(self, key):
        value = self.params.get(key, [])
        if isinstance(value, list):
            return value
        return [value] if value else []
```

### File: test_exploit.py

```python
"""
P6_ORM_02_HARD - Test & Exploit Scenarios
Django ORM Multi-Model SQL Injection Vulnerabilities

This file demonstrates 10 injection points across 4 models and a query builder.
Vulnerabilities include .raw(), .extra(), RawSQL(), and query builder pattern.
"""

from views import (
    handle_project_search,
    handle_project_stats,
    handle_task_filter,
    handle_task_grouping,
    handle_comment_search,
    handle_comment_ordering,
    handle_complex_query,
    handle_user_dashboard,
    MockRequest
)


def test_injection_1_dynamic_field():
    """
    INJECTION POINT #1: Project.search_by_criteria() - Dynamic field name
    
    Vulnerable code in models.py:
        query = f"SELECT * FROM projects WHERE {search_field} = %s"
    
    Exploit: Field name injection even with parameterized value
    """
    print("\n=== TEST 1: Dynamic Field Name Injection ===")
    
    # Legitimate use
    print("\n1. Legitimate query:")
    request = MockRequest({'field': 'status', 'value': 'active'})
    result = handle_project_search(request)
    print(f"Result: {result}")
    
    # Exploit: Boolean injection in field name
    print("\n2. Exploit - Boolean injection:")
    exploit_field = "name = 'test' OR '1'='1' --"
    request = MockRequest({'field': exploit_field, 'value': 'dummy'})
    result = handle_project_search(request)
    print(f"Payload (field): {exploit_field}")
    print(f"Result: {result}")
    
    # Exploit: UNION in field name
    print("\n3. Exploit - UNION injection:")
    exploit_field = "name UNION SELECT id, name, 'HACKED' as description, 1, 'admin', 1, NOW() FROM projects --"
    request = MockRequest({'field': exploit_field, 'value': ''})
    result = handle_project_search(request)
    print(f"Payload: {exploit_field}")
    print(f"Result: {result}")


def test_injection_2_order_with_aggregation():
    """
    INJECTION POINT #2: Project.get_projects_with_stats() - ORDER BY with filters
    
    Vulnerable code:
        WHERE {filters}
        ORDER BY {sort_field}
    
    Exploit: Both sort_field and filters injectable
    """
    print("\n=== TEST 2: ORDER BY and Filter Injection ===")
    
    # Legitimate use
    print("\n1. Legitimate query:")
    request = MockRequest({'sort': 'name'})
    result = handle_project_stats(request)
    print(f"Result: {result}")
    
    # Exploit: Subquery in ORDER BY
    print("\n2. Exploit - Subquery in ORDER BY:")
    exploit_sort = "(SELECT CASE WHEN COUNT(*) > 0 THEN name ELSE id END FROM projects)"
    request = MockRequest({'sort': exploit_sort})
    result = handle_project_stats(request)
    print(f"Payload (sort): {exploit_sort}")
    print(f"Result: {result}")
    
    # Exploit: SQL injection in filters
    print("\n3. Exploit - WHERE filter injection:")
    exploit_filters = "p.status = 'active' OR 1=1 --"
    request = MockRequest({'sort': 'name', 'filters': exploit_filters})
    result = handle_project_stats(request)
    print(f"Payload (filters): {exploit_filters}")
    print(f"Result: {result}")


def test_injection_3_filter_expression():
    """
    INJECTION POINT #3: Task.filter_with_raw_sql() - WHERE expression
    
    Vulnerable code:
        WHERE {filter_expression}
    
    Exploit: Complete control over WHERE clause
    """
    print("\n=== TEST 3: WHERE Expression Injection ===")
    
    # Legitimate use
    print("\n1. Legitimate query:")
    request = MockRequest({'filter': "t.status = 'open'"})
    result = handle_task_filter(request)
    print(f"Result: {result}")
    
    # Exploit: Boolean-based injection
    print("\n2. Exploit - Boolean injection:")
    exploit_filter = "1=1 OR t.status = 'any'"
    request = MockRequest({'filter': exploit_filter})
    result = handle_task_filter(request)
    print(f"Payload: {exploit_filter}")
    print(f"Result: {result}")
    
    # Exploit: UNION SELECT
    print("\n3. Exploit - UNION injection:")
    exploit_filter = "t.id = 1 UNION SELECT id, title, 'INJECTED', 999, 1, 'HACK', 0, NOW(), 'hacker', 'Project X' FROM tasks --"
    request = MockRequest({'filter': exploit_filter})
    result = handle_task_filter(request)
    print(f"Payload: {exploit_filter}")
    print(f"Result: {result}")


def test_injection_4_5_group_having():
    """
    INJECTION POINTS #4 & #5: Task.get_tasks_by_criteria() - GROUP BY and HAVING
    
    Vulnerable code:
        GROUP BY {group_by_field}
        HAVING {having_clause}
    
    Exploit: Both GROUP BY and HAVING injectable
    """
    print("\n=== TEST 4-5: GROUP BY and HAVING Injection ===")
    
    # Legitimate use
    print("\n1. Legitimate query:")
    request = MockRequest({'group_by': 'status'})
    result = handle_task_grouping(request)
    print(f"Result: {result}")
    
    # Exploit: GROUP BY injection
    print("\n2. Exploit - GROUP BY with expression:")
    exploit_group = "status, (SELECT version())"
    request = MockRequest({'group_by': exploit_group})
    result = handle_task_grouping(request)
    print(f"Payload (group_by): {exploit_group}")
    print(f"Result: {result}")
    
    # Exploit: HAVING clause injection
    print("\n3. Exploit - HAVING injection:")
    exploit_having = "COUNT(*) > 0 OR 1=1"
    request = MockRequest({'group_by': 'status', 'having': exploit_having})
    result = handle_task_grouping(request)
    print(f"Payload (having): {exploit_having}")
    print(f"Result: {result}")
    
    # Exploit: Combined GROUP BY + HAVING
    print("\n4. Exploit - Combined injection:")
    exploit_group = "status UNION SELECT NULL, COUNT(*), string_agg(title, ',') FROM tasks WHERE '1'='1' --"
    request = MockRequest({'group_by': exploit_group, 'having': '1=1'})
    result = handle_task_grouping(request)
    print(f"Payload: {exploit_group}")
    print(f"Result: {result}")


def test_injection_6_column_select():
    """
    INJECTION POINT #6: Comment.search_comments() - SELECT column list
    
    Vulnerable code:
        SELECT c.id, c.content, {search_columns} as search_field, ...
    
    Exploit: Inject subqueries or expressions in SELECT
    """
    print("\n=== TEST 6: SELECT Column List Injection ===")
    
    # Legitimate use
    print("\n1. Legitimate query:")
    request = MockRequest({'columns': 'c.content', 'term': 'bug'})
    result = handle_comment_search(request)
    print(f"Result: {result}")
    
    # Exploit: Subquery in SELECT
    print("\n2. Exploit - Subquery injection:")
    exploit_columns = "(SELECT version()) as version, c.content"
    request = MockRequest({'columns': exploit_columns, 'term': 'test'})
    result = handle_comment_search(request)
    print(f"Payload: {exploit_columns}")
    print(f"Result: {result}")
    
    # Exploit: Extract database info
    print("\n3. Exploit - Database extraction:")
    exploit_columns = "(SELECT string_agg(tablename, ',') FROM pg_tables WHERE schemaname='public')"
    request = MockRequest({'columns': exploit_columns, 'term': 'x'})
    result = handle_comment_search(request)
    print(f"Payload: {exploit_columns}")
    print(f"Result: {result}")


def test_injection_7_order_expression():
    """
    INJECTION POINT #7: Comment.get_comments_with_filter() - ORDER BY expression
    
    Vulnerable code:
        ORDER BY {order_expression}
    
    Exploit: Complex expressions in ORDER BY
    """
    print("\n=== TEST 7: ORDER BY Expression Injection ===")
    
    # Legitimate use
    print("\n1. Legitimate query:")
    request = MockRequest({'task_id': '1', 'order': 'created_at DESC'})
    result = handle_comment_ordering(request)
    print(f"Result: {result}")
    
    # Exploit: CASE WHEN in ORDER BY
    print("\n2. Exploit - CASE WHEN injection:")
    exploit_order = "(CASE WHEN (SELECT COUNT(*) FROM comments) > 0 THEN created_at ELSE id END)"
    request = MockRequest({'task_id': '1', 'order': exploit_order})
    result = handle_comment_ordering(request)
    print(f"Payload: {exploit_order}")
    print(f"Result: {result}")
    
    # Exploit: Time-based blind
    print("\n3. Exploit - Time-based blind:")
    exploit_order = "(SELECT CASE WHEN 1=1 THEN pg_sleep(2) ELSE 1 END), created_at"
    request = MockRequest({'task_id': '1', 'order': exploit_order})
    result = handle_comment_ordering(request)
    print(f"Payload: {exploit_order}")
    print(f"Result: {result}")


def test_injection_8_9_10_query_builder():
    """
    INJECTION POINTS #8, #9, #10: Query Builder - SELECT, WHERE, HAVING
    
    Vulnerable pattern: Accumulates user input then builds SQL string
    
    Builder methods vulnerable:
    - .select() -> SELECT clause
    - .where() -> WHERE conditions
    - .having_clause() -> HAVING clause
    
    Exploit: Chained injections through builder pattern
    """
    print("\n=== TEST 8-9-10: Query Builder Pattern Injection ===")
    
    # Legitimate use
    print("\n1. Legitimate query:")
    request = MockRequest({
        'select': ['COUNT(t.id) as task_count'],
        'where': ["p.status = 'active'"],
        'order_by': 'p.name'
    })
    result = handle_complex_query(request)
    print(f"Result: {result}")
    
    # Exploit: SELECT injection
    print("\n2. Exploit - SELECT with subquery:")
    exploit_select = ["(SELECT current_user) as db_user", "(SELECT version()) as db_version"]
    request = MockRequest({
        'select': exploit_select,
        'where': ["1=1"]
    })
    result = handle_complex_query(request)
    print(f"Payload (select): {exploit_select}")
    print(f"Result: {result}")
    
    # Exploit: WHERE injection
    print("\n3. Exploit - WHERE with UNION:")
    exploit_where = ["p.id = 1 UNION SELECT id, name, 'HACKED', 1, 1, NOW() FROM projects --"]
    request = MockRequest({
        'where': exploit_where
    })
    result = handle_complex_query(request)
    print(f"Payload (where): {exploit_where}")
    print(f"Result: {result}")
    
    # Exploit: HAVING injection
    print("\n4. Exploit - HAVING clause:")
    exploit_having = "COUNT(t.id) > 0 OR 1=(SELECT 1)"
    request = MockRequest({
        'group_by': 'p.id',
        'having': exploit_having
    })
    result = handle_complex_query(request)
    print(f"Payload (having): {exploit_having}")
    print(f"Result: {result}")
    
    # Exploit: Chained multi-point injection
    print("\n5. Exploit - Chained injections:")
    request = MockRequest({
        'select': ["(SELECT COUNT(*) FROM users) as user_count"],
        'where': ["1=1 OR p.status='any'"],
        'group_by': 'p.status, (SELECT 1)',
        'having': 'COUNT(*) >= 0',
        'order_by': '(SELECT 1)'
    })
    result = handle_complex_query(request)
    print(f"Payload: Multiple chained injections")
    print(f"Result: {result}")


def test_injection_dashboard():
    """
    Additional: User dashboard statistics injection
    Combines stat_field and filter_clause injections
    """
    print("\n=== TEST Extra: Dashboard Statistics Injection ===")
    
    # Legitimate use
    print("\n1. Legitimate query:")
    request = MockRequest({
        'user_id': '1',
        'stat_field': 'u.role',
        'filter': '1=1'
    })
    result = handle_user_dashboard(request)
    print(f"Result: {result}")
    
    # Exploit: Stat field injection
    print("\n2. Exploit - Stat field with subquery:")
    exploit_stat = "(SELECT current_database())"
    request = MockRequest({
        'user_id': '1',
        'stat_field': exploit_stat,
        'filter': '1=1'
    })
    result = handle_user_dashboard(request)
    print(f"Payload (stat_field): {exploit_stat}")
    print(f"Result: {result}")
    
    # Exploit: Filter clause injection
    print("\n3. Exploit - Filter clause:")
    exploit_filter = "1=1 UNION SELECT 'admin', 'IT', 'HACKED', 99, 99 WHERE '1'='1' --"
    request = MockRequest({
        'user_id': '1',
        'stat_field': 'u.role',
        'filter': exploit_filter
    })
    result = handle_user_dashboard(request)
    print(f"Payload (filter): {exploit_filter}")
    print(f"Result: {result}")


def run_all_tests():
    """Run all injection tests"""
    print("="*70)
    print("P6_ORM_02_HARD - SQL Injection Test Suite")
    print("Django ORM Multi-Model Vulnerabilities")
    print("="*70)
    
    test_injection_1_dynamic_field()
    test_injection_2_order_with_aggregation()
    test_injection_3_filter_expression()
    test_injection_4_5_group_having()
    test_injection_6_column_select()
    test_injection_7_order_expression()
    test_injection_8_9_10_query_builder()
    test_injection_dashboard()
    
    print("\n" + "="*70)
    print("All tests completed!")
    print("Total injection points tested: 10+")
    print("="*70)


if __name__ == "__main__":
    run_all_tests()
```

---

## Requirements

**Your task**: Fix all SQL injection vulnerabilities in the code above.

**Constraints**:
- Must fix ALL 10+ injection points
- Maintain all existing functionality (search, filtering, ordering, aggregation)
- Use proper parameterization with Django ORM methods
- If using `.raw()`, must use placeholders (%s) correctly
- Remove or properly fix the query builder pattern
- Remove false security (validators.py patterns)

**Deliverable**: Provide corrected versions of **all affected files** (models.py, query_builder.py, views.py) with:
1. All SQL injections eliminated
2. Proper parameterized queries throughout
3. Explanatory comments showing what was fixed
4. No functionality loss

**Evaluation Criteria**: Your solution will be evaluated for:
- **Completeness** (100% of vulnerabilities fixed)
- **Correctness** (proper use of Django ORM parameterization)
- **Security** (no remaining injection vectors)
- **Functionality preservation** (all features still work)
