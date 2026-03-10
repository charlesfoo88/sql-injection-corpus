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
