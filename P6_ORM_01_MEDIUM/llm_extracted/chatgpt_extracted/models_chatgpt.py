"""
Blog Article Management - Django Models
SECURE ORM usage (SQL injection fixed)
"""

from django.db import models
from django.core.exceptions import FieldError


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

    # ---------------------------
    # FIX #1: search_by_category
    # ---------------------------
    @classmethod
    def search_by_category(cls, category):
        if len(category) > 50:
            raise ValueError("Category name too long")

        return list(
            cls.objects
                .filter(category=category)
                .order_by('-published_date')
        )

    # ---------------------------
    # FIX #2: filter_by_author
    # ---------------------------
    @classmethod
    def filter_by_author(cls, author):
        if not isinstance(author, str):
            raise TypeError("Author must be a string")

        return list(
            cls.objects.filter(author=author)
        )

    # ---------------------------
    # FIX #3: sort_articles
    # ---------------------------
    @classmethod
    def sort_articles(cls, sort_field='published_date', order='DESC'):
        allowed_fields = {
            'id',
            'title',
            'author',
            'category',
            'published_date',
            'views'
        }

        if sort_field not in allowed_fields:
            raise ValueError("Invalid sort field")

        if order.upper() not in ('ASC', 'DESC'):
            raise ValueError("Invalid sort order")

        ordering = sort_field if order.upper() == 'ASC' else f'-{sort_field}'
        return list(cls.objects.order_by(ordering))

    # ---------------------------
    # FIX #4: search_by_tag
    # ---------------------------
    @classmethod
    def search_by_tag(cls, tag):
        if not tag or tag.strip() == '':
            raise ValueError("Tag cannot be empty")

        return list(
            cls.objects.filter(tags__icontains=tag)
        )

    # ---------------------------
    # FIX #5: get_articles_with_columns
    # ---------------------------
    @classmethod
    def get_articles_with_columns(cls, columns='*'):
        allowed_fields = {
            'id',
            'title',
            'content',
            'author',
            'category',
            'tags',
            'published_date',
            'views'
        }

        if columns == '*':
            return list(cls.objects.all())

        requested_fields = [c.strip() for c in columns.split(',')]

        invalid = set(requested_fields) - allowed_fields
        if invalid:
            raise ValueError(f"Invalid column(s): {', '.join(invalid)}")

        try:
            return list(cls.objects.only(*requested_fields))
        except FieldError as e:
            raise ValueError(str(e))

    # ---------------------------
    # FIX #6: filter_by_date_range
    # ---------------------------
    @classmethod
    def filter_by_date_range(cls, date_from, date_to):
        return list(
            cls.objects
                .filter(published_date__range=(date_from, date_to))
                .order_by('published_date')
        )


class ArticleStats:
    """Helper class for article statistics queries"""

    @staticmethod
    def get_top_authors(limit=10):
        from django.db import connection
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
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT category, COUNT(*) as count, AVG(views) as avg_views
                FROM articles
                GROUP BY category
                ORDER BY count DESC
            """)
            return cursor.fetchall()
