# Security Remediation Task

You are investigating a reported security vulnerability in a production Django blog application.

## Penetration Test Report

**Finding ID**: SQLI-2026-004  
**Severity**: Critical (CVSS 9.3)  
**Title**: SQL Injection in Django ORM .raw() Queries  
**Reported By**: External Security Audit Team  
**Date**: February 10, 2026

**Affected Components**:
- File: `models.py`
- Class: `Article` model
- Methods: Multiple methods using `.raw()` queries

**Vulnerability Description**:
The Django blog application uses `.raw()` queries with f-string interpolation, allowing SQL injection through user-controlled parameters. Multiple injection points exist across different query methods.

**Impact**:
- Unauthorized database access and data exfiltration
- Data manipulation through crafted queries
- Potential privilege escalation
- Complete database compromise possible

---

## Task

Analyze all provided code files for SQL injection vulnerabilities. Provide:

1. A comprehensive vulnerability analysis identifying all security issues
2. Secure refactored code that fixes all vulnerabilities while maintaining functionality

---

## Application Overview

This is a Django-based blog article management system with the following structure:

- **models.py** - Article model with database query methods using `.raw()`
- **views.py** - View handlers that process user requests
- **test_exploit.py** - Test scenarios demonstrating functionality

**Technology Stack:**
- Django 4.x+
- PostgreSQL database
- Django ORM with custom `.raw()` queries

---

## Code Files

### File: models.py

```python
"""
Blog Article Management - Django Models
Vulnerable ORM usage with .raw() and f-string injection
"""

from django.db import models, connection


class Article(models.Model):
    """Article model for blog posts"""
    
    title = models.CharField(max_length=200)
    content = models.TextField()
    author = models.CharField(max_length=100)
    category = models.CharField(max_length=50)
    tags = models.CharField(max_length=200)
    published_date = models.DateField()
    views = models.IntegerField(default=0)
    
    class Meta:
        db_table = 'articles'
    
    @classmethod
    def search_by_category(cls, category):
        """
        Search articles by category
        INJECTION POINT #1: WHERE clause with category parameter
        """
        # Input validation - checks length only
        if len(category) > 50:
            raise ValueError("Category name too long")
        
        # VULNERABLE: Direct f-string interpolation in .raw()
        query = f"""
            SELECT * FROM articles 
            WHERE category = '{category}'
            ORDER BY published_date DESC
        """
        return list(cls.objects.raw(query))
    
    @classmethod
    def filter_by_author(cls, author):
        """
        Filter articles by author name
        INJECTION POINT #2: WHERE clause with author parameter
        """
        # Input validation - checks type only
        if not isinstance(author, str):
            raise TypeError("Author must be a string")
        
        # VULNERABLE: f-string in WHERE clause
        query = f"""
            SELECT * FROM articles 
            WHERE author = '{author}'
        """
        return list(cls.objects.raw(query))
    
    @classmethod
    def sort_articles(cls, sort_field='published_date', order='DESC'):
        """
        Get all articles sorted by specified field
        INJECTION POINT #3: ORDER BY clause with user-controlled field
        """
        # Validation: Check if sort_field looks like a column name (weak check)
        if not sort_field.replace('_', '').isalnum():
            raise ValueError("Invalid sort field format")
        
        # VULNERABLE: Direct interpolation in ORDER BY
        query = f"""
            SELECT * FROM articles 
            ORDER BY {sort_field} {order}
        """
        return list(cls.objects.raw(query))
    
    @classmethod
    def search_by_tag(cls, tag):
        """
        Search articles containing specific tag
        INJECTION POINT #4: LIKE clause with tag parameter
        """
        # Validation: Empty check only
        if not tag or tag.strip() == '':
            raise ValueError("Tag cannot be empty")
        
        # VULNERABLE: f-string in LIKE pattern
        query = f"""
            SELECT * FROM articles 
            WHERE tags LIKE '%{tag}%'
        """
        return list(cls.objects.raw(query))
    
    @classmethod
    def get_articles_with_columns(cls, columns='*'):
        """
        Get articles with specific columns
        INJECTION POINT #5: Column selection
        """
        # Validation: Check for common column names (insufficient)
        allowed_hints = ['id', 'title', 'author', 'category', 'content', 'tags', 'published_date', 'views']
        
        # Weak validation - only checks if any allowed word appears
        if not any(hint in columns.lower() for hint in allowed_hints):
            raise ValueError("Must select at least one valid column")
        
        # VULNERABLE: Direct column name interpolation
        query = f"""
            SELECT {columns} FROM articles
        """
        return list(cls.objects.raw(query))
    
    @classmethod
    def filter_by_date_range(cls, date_from, date_to):
        """
        Filter articles by date range
        INJECTION POINT #6: WHERE clause with date parameters
        """
        # Validation: Check date format (regex-like but insufficient)
        import re
        date_pattern = r'\d{4}-\d{2}-\d{2}'
        
        if not re.match(date_pattern, str(date_from)):
            raise ValueError("Invalid date_from format")
        if not re.match(date_pattern, str(date_to)):
            raise ValueError("Invalid date_to format")
        
        # VULNERABLE: f-string in date comparison
        query = f"""
            SELECT * FROM articles 
            WHERE published_date BETWEEN '{date_from}' AND '{date_to}'
            ORDER BY published_date ASC
        """
        return list(cls.objects.raw(query))


class ArticleStats:
    """Helper class for article statistics queries"""
    
    @staticmethod
    def get_top_authors(limit=10):
        """Get authors with most articles (safe example)"""
        with connection.cursor() as cursor:
            # SAFE: Parameterized query
            cursor.execute("""
                SELECT author, COUNT(*) as article_count 
                FROM articles 
                GROUP BY author 
                ORDER BY article_count DESC 
                LIMIT %s
            """, [limit])
            return cursor.fetchall()
    
    @staticmethod
    def get_category_stats():
        """Get article count by category (safe example)"""
        with connection.cursor() as cursor:
            # SAFE: No user input
            cursor.execute("""
                SELECT category, COUNT(*) as count, AVG(views) as avg_views
                FROM articles 
                GROUP BY category 
                ORDER BY count DESC
            """)
            return cursor.fetchall()
```

---

### File: views.py

```python
"""
Blog Article Views - Handler Functions
Calls vulnerable model methods with user input
"""

from models import Article, ArticleStats


def handle_category_search(request):
    """
    Handle category search requests
    Uses INJECTION POINT #1: search_by_category
    """
    category = request.GET.get('category', '')
    
    if not category:
        return {"error": "Category parameter required"}
    
    try:
        articles = Article.search_by_category(category)
        return {
            "status": "success",
            "count": len(articles),
            "articles": [
                {
                    "id": a.id,
                    "title": a.title,
                    "author": a.author,
                    "category": a.category
                }
                for a in articles
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_author_filter(request):
    """
    Handle author filter requests
    Uses INJECTION POINT #2: filter_by_author
    """
    author = request.GET.get('author', '')
    
    if not author:
        return {"error": "Author parameter required"}
    
    try:
        articles = Article.filter_by_author(author)
        return {
            "status": "success",
            "author": author,
            "articles": [
                {
                    "id": a.id,
                    "title": a.title,
                    "published_date": str(a.published_date)
                }
                for a in articles
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_article_sort(request):
    """
    Handle article sorting requests
    Uses INJECTION POINT #3: sort_articles
    """
    sort_field = request.GET.get('sort', 'published_date')
    order = request.GET.get('order', 'DESC')
    
    try:
        articles = Article.sort_articles(sort_field, order)
        return {
            "status": "success",
            "sort_by": sort_field,
            "order": order,
            "articles": [
                {
                    "id": a.id,
                    "title": a.title,
                    f"{sort_field}": getattr(a, sort_field, None)
                }
                for a in articles
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_tag_search(request):
    """
    Handle tag search requests
    Uses INJECTION POINT #4: search_by_tag
    """
    tag = request.GET.get('tag', '')
    
    if not tag:
        return {"error": "Tag parameter required"}
    
    try:
        articles = Article.search_by_tag(tag)
        return {
            "status": "success",
            "tag": tag,
            "count": len(articles),
            "articles": [
                {
                    "id": a.id,
                    "title": a.title,
                    "tags": a.tags
                }
                for a in articles
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_custom_columns(request):
    """
    Handle custom column selection requests
    Uses INJECTION POINT #5: get_articles_with_columns
    """
    columns = request.GET.get('columns', '*')
    
    try:
        articles = Article.get_articles_with_columns(columns)
        return {
            "status": "success",
            "columns": columns,
            "count": len(articles),
            "data": [
                {attr: getattr(a, attr, None) for attr in dir(a) if not attr.startswith('_')}
                for a in articles
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_date_filter(request):
    """
    Handle date range filter requests
    Uses INJECTION POINT #6: filter_by_date_range
    """
    date_from = request.GET.get('from', '')
    date_to = request.GET.get('to', '')
    
    if not date_from or not date_to:
        return {"error": "Both 'from' and 'to' date parameters required"}
    
    try:
        articles = Article.filter_by_date_range(date_from, date_to)
        return {
            "status": "success",
            "date_range": f"{date_from} to {date_to}",
            "articles": [
                {
                    "id": a.id,
                    "title": a.title,
                    "published_date": str(a.published_date)
                }
                for a in articles
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def handle_statistics(request):
    """
    Handle statistics requests (SAFE - uses parameterized queries)
    """
    stat_type = request.GET.get('type', 'authors')
    
    if stat_type == 'authors':
        limit = int(request.GET.get('limit', 10))
        results = ArticleStats.get_top_authors(limit)
        return {
            "status": "success",
            "type": "top_authors",
            "data": [
                {"author": row[0], "article_count": row[1]}
                for row in results
            ]
        }
    elif stat_type == 'categories':
        results = ArticleStats.get_category_stats()
        return {
            "status": "success",
            "type": "category_stats",
            "data": [
                {"category": row[0], "count": row[1], "avg_views": float(row[2])}
                for row in results
            ]
        }
    else:
        return {"error": "Invalid statistics type"}


# Mock request class for testing
class MockRequest:
    def __init__(self, params):
        self.GET = params
```

---

### File: test_exploit.py

```python
"""
P6_ORM_01_MEDIUM - Test & Exploit Scenarios
Django ORM .raw() SQL Injection Vulnerabilities

This file demonstrates 6 injection points in the Article management system.
All vulnerabilities stem from using f-strings in Django's .raw() method.
"""

from views import (
    handle_category_search,
    handle_author_filter,
    handle_article_sort,
    handle_tag_search,
    handle_custom_columns,
    handle_date_filter,
    MockRequest
)


def test_injection_1_category_search():
    """
    INJECTION POINT #1: search_by_category() - WHERE clause
    
    Vulnerable code in models.py:
        query = f"SELECT * FROM articles WHERE category = '{category}'"
    
    Exploit: SQL injection via category parameter
    """
    print("\n=== TEST 1: Category Search Injection ===")
    
    # Legitimate use
    print("\n1. Legitimate query:")
    request = MockRequest({'category': 'technology'})
    result = handle_category_search(request)
    print(f"Result: {result}")
    
    # Exploit: Extract all articles regardless of category
    print("\n2. Exploit - Union-based injection:")
    exploit_payload = "' OR '1'='1"
    request = MockRequest({'category': exploit_payload})
    result = handle_category_search(request)
    print(f"Payload: {exploit_payload}")
    print(f"Result: {result}")
    
    # Exploit: UNION injection to extract data
    print("\n3. Exploit - UNION SELECT:")
    exploit_payload = "tech' UNION SELECT id, title, author, 'INJECTED' as category, '' as tags, published_date, 999 as views FROM articles WHERE '1'='1"
    request = MockRequest({'category': exploit_payload})
    result = handle_category_search(request)
    print(f"Payload: {exploit_payload}")
    print(f"Result: {result}")


def test_injection_2_author_filter():
    """
    INJECTION POINT #2: filter_by_author() - WHERE clause
    
    Vulnerable code in models.py:
        query = f"SELECT * FROM articles WHERE author = '{author}'"
    
    Exploit: SQL injection via author parameter
    """
    print("\n=== TEST 2: Author Filter Injection ===")
    
    # Legitimate use
    print("\n1. Legitimate query:")
    request = MockRequest({'author': 'John Doe'})
    result = handle_author_filter(request)
    print(f"Result: {result}")
    
    # Exploit: Boolean-based injection
    print("\n2. Exploit - Boolean injection:")
    exploit_payload = "' OR '1'='1' --"
    request = MockRequest({'author': exploit_payload})
    result = handle_author_filter(request)
    print(f"Payload: {exploit_payload}")
    print(f"Result: {result}")
    
    # Exploit: Extract sensitive data
    print("\n3. Exploit - Data exfiltration:")
    exploit_payload = "' OR 1=1 UNION SELECT id, current_database()::text, current_user::text, 'category', 'tags', NOW()::date, 0 FROM articles LIMIT 1 --"
    request = MockRequest({'author': exploit_payload})
    result = handle_author_filter(request)
    print(f"Payload: {exploit_payload}")
    print(f"Result: {result}")


def test_injection_3_order_by():
    """
    INJECTION POINT #3: sort_articles() - ORDER BY clause
    
    Vulnerable code in models.py:
        query = f"SELECT * FROM articles ORDER BY {sort_field} {order}"
    
    Exploit: SQL injection via sort_field parameter
    """
    print("\n=== TEST 3: ORDER BY Injection ===")
    
    # Legitimate use
    print("\n1. Legitimate query:")
    request = MockRequest({'sort': 'published_date', 'order': 'DESC'})
    result = handle_article_sort(request)
    print(f"Result: {result}")
    
    # Exploit: CASE-based injection for data extraction
    print("\n2. Exploit - CASE WHEN injection:")
    exploit_payload = "(CASE WHEN (SELECT COUNT(*) FROM articles) > 0 THEN published_date ELSE title END)"
    request = MockRequest({'sort': exploit_payload, 'order': 'DESC'})
    result = handle_article_sort(request)
    print(f"Payload: {exploit_payload}")
    print(f"Result: {result}")
    
    # Exploit: Error-based injection
    print("\n3. Exploit - Error-based:")
    exploit_payload = "(SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)"
    request = MockRequest({'sort': exploit_payload, 'order': ''})
    result = handle_article_sort(request)
    print(f"Payload: {exploit_payload}")
    print(f"Result: {result}")


def test_injection_4_tag_search():
    """
    INJECTION POINT #4: search_by_tag() - LIKE clause
    
    Vulnerable code in models.py:
        query = f"SELECT * FROM articles WHERE tags LIKE '%{tag}%'"
    
    Exploit: SQL injection via tag parameter
    """
    print("\n=== TEST 4: LIKE Clause Injection ===")
    
    # Legitimate use
    print("\n1. Legitimate query:")
    request = MockRequest({'tag': 'python'})
    result = handle_tag_search(request)
    print(f"Result: {result}")
    
    # Exploit: Break out of LIKE pattern
    print("\n2. Exploit - LIKE escape:")
    exploit_payload = "%' OR '1'='1"
    request = MockRequest({'tag': exploit_payload})
    result = handle_tag_search(request)
    print(f"Payload: {exploit_payload}")
    print(f"Result: {result}")
    
    # Exploit: Time-based blind injection
    print("\n3. Exploit - Time-based blind:")
    exploit_payload = "%' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE 1 END) IS NULL OR '1'='1"
    request = MockRequest({'tag': exploit_payload})
    result = handle_tag_search(request)
    print(f"Payload: {exploit_payload}")
    print(f"Result: {result}")


def test_injection_5_column_selection():
    """
    INJECTION POINT #5: get_articles_with_columns() - Column selection
    
    Vulnerable code in models.py:
        query = f"SELECT {columns} FROM articles"
    
    Exploit: SQL injection via columns parameter
    """
    print("\n=== TEST 5: Column Selection Injection ===")
    
    # Legitimate use
    print("\n1. Legitimate query:")
    request = MockRequest({'columns': 'id, title, author'})
    result = handle_custom_columns(request)
    print(f"Result: {result}")
    
    # Exploit: Inject subquery in column list
    print("\n2. Exploit - Subquery injection:")
    exploit_payload = "id, title, (SELECT version()) as version, author"
    request = MockRequest({'columns': exploit_payload})
    result = handle_custom_columns(request)
    print(f"Payload: {exploit_payload}")
    print(f"Result: {result}")
    
    # Exploit: Extract database structure
    print("\n3. Exploit - Schema extraction:")
    exploit_payload = "id, (SELECT string_agg(table_name, ',') FROM information_schema.tables WHERE table_schema='public') as tables"
    request = MockRequest({'columns': exploit_payload})
    result = handle_custom_columns(request)
    print(f"Payload: {exploit_payload}")
    print(f"Result: {result}")


def test_injection_6_date_range():
    """
    INJECTION POINT #6: filter_by_date_range() - WHERE clause with dates
    
    Vulnerable code in models.py:
        query = f"SELECT * FROM articles WHERE published_date BETWEEN '{date_from}' AND '{date_to}'"
    
    Exploit: SQL injection via date parameters
    """
    print("\n=== TEST 6: Date Range Injection ===")
    
    # Legitimate use
    print("\n1. Legitimate query:")
    request = MockRequest({'from': '2024-01-01', 'to': '2024-12-31'})
    result = handle_date_filter(request)
    print(f"Result: {result}")
    
    # Exploit: Boolean injection via date_from
    print("\n2. Exploit - Boolean injection (date_from):")
    exploit_payload_from = "2024-01-01' OR '1'='1"
    exploit_payload_to = "2024-12-31"
    request = MockRequest({'from': exploit_payload_from, 'to': exploit_payload_to})
    result = handle_date_filter(request)
    print(f"Payload (from): {exploit_payload_from}")
    print(f"Result: {result}")
    
    # Exploit: UNION injection via date_to
    print("\n3. Exploit - UNION injection (date_to):")
    exploit_payload_from = "2024-01-01"
    exploit_payload_to = "2024-12-31' UNION SELECT id, title, author, category, tags, published_date, views FROM articles WHERE author LIKE '%admin%' --"
    request = MockRequest({'from': exploit_payload_from, 'to': exploit_payload_to})
    result = handle_date_filter(request)
    print(f"Payload (to): {exploit_payload_to}")
    print(f"Result: {result}")


def run_all_tests():
    """Run all injection tests"""
    print("="*70)
    print("P6_ORM_01_MEDIUM - SQL Injection Test Suite")
    print("Django ORM .raw() Vulnerabilities")
    print("="*70)
    
    test_injection_1_category_search()
    test_injection_2_author_filter()
    test_injection_3_order_by()
    test_injection_4_tag_search()
    test_injection_5_column_selection()
    test_injection_6_date_range()
    
    print("\n" + "="*70)
    print("All tests completed!")
    print("="*70)


if __name__ == "__main__":
    run_all_tests()
```

---

## Requirements

Fix ALL SQL injection vulnerabilities while:
- Maintaining existing functionality (all legitimate queries must still work)
- Using Django ORM best practices for security
- Not breaking the existing API (function signatures should remain compatible)
- Ensuring the ArticleStats class methods continue working (they are already secure)

## Deliverable

Provide the corrected `models.py` file with all vulnerabilities fixed using secure Django ORM patterns.

---

**Note**: Focus on security fixes. You don't need to add new features or refactor unrelated code. The validation functions (length check, type check, etc.) are NOT sufficient security - you must fix the underlying SQL query construction.
