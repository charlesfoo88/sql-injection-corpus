"""
Blog Article Management - Django Models (SECURE VERSION)
Fixed: All SQL injection vulnerabilities using parameterized queries
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
        app_label = '__main__'  # Allow Django to use model without INSTALLED_APPS
    
    @classmethod
    def search_by_category(cls, category):
        """
        Search articles by category
        FIXED: Uses parameterized query instead of f-string interpolation
        """
        # Input validation - retained from original
        if len(category) > 50:
            raise ValueError("Category name too long")
        
        # SECURE: Parameterized query with %s placeholder
        query = """
            SELECT * FROM articles 
            WHERE category = %s
            ORDER BY published_date DESC
        """
        return list(cls.objects.raw(query, [category]))
    
    @classmethod
    def filter_by_author(cls, author):
        """
        Filter articles by author name
        FIXED: Uses parameterized query instead of f-string interpolation
        """
        # Input validation - retained from original
        if not isinstance(author, str):
            raise TypeError("Author must be a string")
        
        # SECURE: Parameterized query with %s placeholder
        query = """
            SELECT * FROM articles 
            WHERE author = %s
        """
        return list(cls.objects.raw(query, [author]))
    
    @classmethod
    def sort_articles(cls, sort_field='published_date', order='DESC'):
        """
        Get all articles sorted by specified field
        FIXED: Uses allowlist validation + safe SQL construction
        
        Note: ORDER BY cannot use parameterized placeholders in PostgreSQL/Django,
        so we use strict allowlist validation instead
        """
        # SECURE: Strict allowlist for sort_field
        ALLOWED_SORT_FIELDS = {
            'id', 'title', 'author', 'category', 
            'tags', 'published_date', 'views', 'content'
        }
        
        if sort_field not in ALLOWED_SORT_FIELDS:
            raise ValueError(f"Invalid sort field. Allowed: {', '.join(ALLOWED_SORT_FIELDS)}")
        
        # SECURE: Strict allowlist for order direction
        ALLOWED_ORDER = {'ASC', 'DESC'}
        order_upper = order.upper()
        
        if order_upper not in ALLOWED_ORDER:
            raise ValueError(f"Invalid order direction. Allowed: ASC, DESC")
        
        # SECURE: Safe SQL construction with validated identifiers
        # SQL identifiers (column names, ORDER direction) cannot be parameterized,
        # but we've validated them against strict allowlists
        query = f"""
            SELECT * FROM articles 
            ORDER BY {sort_field} {order_upper}
        """
        return list(cls.objects.raw(query))
    
    @classmethod
    def search_by_tag(cls, tag):
        """
        Search articles containing specific tag
        FIXED: Uses parameterized query for LIKE pattern
        """
        # Validation - retained from original
        if not tag or tag.strip() == '':
            raise ValueError("Tag cannot be empty")
        
        # SECURE: Parameterized query with LIKE pattern
        # The % wildcards are part of the parameter value, not SQL code
        query = """
            SELECT * FROM articles 
            WHERE tags LIKE %s
        """
        # Construct LIKE pattern as a parameter value
        like_pattern = f'%{tag}%'
        return list(cls.objects.raw(query, [like_pattern]))
    
    @classmethod
    def get_articles_with_columns(cls, columns='*'):
        """
        Get articles with specific columns
        FIXED: Uses allowlist validation for column selection
        
        Note: Column names in SELECT clause cannot be parameterized,
        so we validate against an allowlist and construct safe SQL
        """
        # SECURE: Define allowed columns
        ALLOWED_COLUMNS = {
            'id', 'title', 'author', 'category', 
            'content', 'tags', 'published_date', 'views'
        }
        
        # Handle wildcard case
        if columns.strip() == '*':
            selected_columns = '*'
        else:
            # Parse comma-separated column names
            requested_cols = [col.strip() for col in columns.split(',')]
            
            # Validate each column against allowlist
            invalid_cols = [col for col in requested_cols if col not in ALLOWED_COLUMNS]
            if invalid_cols:
                raise ValueError(
                    f"Invalid columns: {', '.join(invalid_cols)}. "
                    f"Allowed: {', '.join(ALLOWED_COLUMNS)}"
                )
            
            # SECURE: Reconstruct column list from validated identifiers
            selected_columns = ', '.join(requested_cols)
        
        # SECURE: SQL construction with validated identifiers
        query = f"""
            SELECT {selected_columns} FROM articles
        """
        return list(cls.objects.raw(query))
    
    @classmethod
    def filter_by_date_range(cls, date_from, date_to):
        """
        Filter articles by date range
        FIXED: Uses parameterized query for date values
        """
        # Validation - retained from original (still useful for early error detection)
        import re
        date_pattern = r'\d{4}-\d{2}-\d{2}'
        
        if not re.match(date_pattern, str(date_from)):
            raise ValueError("Invalid date_from format")
        if not re.match(date_pattern, str(date_to)):
            raise ValueError("Invalid date_to format")
        
        # SECURE: Parameterized query with %s placeholders for dates
        query = """
            SELECT * FROM articles 
            WHERE published_date BETWEEN %s AND %s
            ORDER BY published_date ASC
        """
        return list(cls.objects.raw(query, [date_from, date_to]))


class ArticleStats:
    """Helper class for article statistics queries"""
    
    @staticmethod
    def get_top_authors(limit=10):
        """Get authors with most articles (already secure)"""
        with connection.cursor() as cursor:
            # SECURE: Already uses parameterized query
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
        """Get article count by category (already secure)"""
        with connection.cursor() as cursor:
            # SECURE: No user input involved
            cursor.execute("""
                SELECT category, COUNT(*) as count, AVG(views) as avg_views
                FROM articles 
                GROUP BY category 
                ORDER BY count DESC
            """)
            return cursor.fetchall()
