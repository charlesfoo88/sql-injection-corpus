"""
Blog Article Management - Django Models
SECURE IMPLEMENTATION: Replaced f-string interpolation with 
parameterized queries and Django ORM QuerySet API.
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
        app_label = '__main__'
    
    @classmethod
    def search_by_category(cls, category):
        """
        FIXED: Using Django QuerySet API (auto-parameterized)
        """
        # Maintain length validation as a secondary layer
        if len(category) > 50:
            raise ValueError("Category name too long")
        
        return list(cls.objects.filter(category=category).order_by('-published_date'))
    
    @classmethod
    def filter_by_author(cls, author):
        """
        FIXED: Using Django QuerySet API
        """
        if not isinstance(author, str):
            raise TypeError("Author must be a string")
        
        return list(cls.objects.filter(author=author))
    
    @classmethod
    def sort_articles(cls, sort_field='published_date', order='DESC'):
        """
        FIXED: Strict allow-listing for dynamic column names
        """
        allowed_fields = ['id', 'title', 'author', 'category', 'published_date', 'views']
        
        if sort_field not in allowed_fields:
            raise ValueError("Invalid sort field")
        
        # Apply descending order prefix if requested
        ordering = f"-{sort_field}" if order.upper() == 'DESC' else sort_field
        
        return list(cls.objects.all().order_by(ordering))
    
    @classmethod
    def search_by_tag(cls, tag):
        """
        FIXED: Using .raw() with proper parameterization 
        """
        if not tag or tag.strip() == '':
            raise ValueError("Tag cannot be empty")
        
        # Note: The %s is handled by the DB driver, ensuring the value is escaped.
        # Use %% to escape the literal percent sign in the SQL string.
        query = "SELECT * FROM articles WHERE tags LIKE %s"
        params = [f"%{tag}%"]
        
        return list(cls.objects.raw(query, params))
    
    @classmethod
    def get_articles_with_columns(cls, columns='*'):
        """
        FIXED: Allow-listing columns for dynamic selection
        """
        allowed_columns = {'id', 'title', 'author', 'category', 'content', 'tags', 'published_date', 'views'}
        
        if columns == '*':
            return list(cls.objects.all())
            
        # Parse user columns and validate against allow-list
        requested = [c.strip() for c in columns.split(',')]
        if not all(col in allowed_columns for col in requested):
            raise ValueError("Invalid column selection detected")
        
        # Use .only() for efficient specific column selection in ORM
        return list(cls.objects.only(*requested))
    
    @classmethod
    def filter_by_date_range(cls, date_from, date_to):
        """
        FIXED: Using Django ORM range filter
        """
        # The ORM handles date object conversion and SQL parameterization
        return list(cls.objects.filter(published_date__range=(date_from, date_to)).order_by('published_date'))


class ArticleStats:
    """Helper class for article statistics queries (Already Secure)"""
    
    @staticmethod
    def get_top_authors(limit=10):
        with connection.cursor() as cursor:
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
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT category, COUNT(*) as count, AVG(views) as avg_views
                FROM articles 
                GROUP BY category 
                ORDER BY count DESC
            """)
            return cursor.fetchall()
