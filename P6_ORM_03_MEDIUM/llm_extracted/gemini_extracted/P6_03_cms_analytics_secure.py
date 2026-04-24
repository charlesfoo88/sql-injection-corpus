"""
Analytics module for article CMS system.
Provides reporting and statistical analysis on article data.
"""

from django.db import models
from django.db.models import F, ExpressionWrapper, FloatField


class Author(models.Model):
    """Author model for CMS users"""
    name = models.CharField(max_length=100)
    email = models.EmailField()
    bio = models.TextField(blank=True)

    class Meta:
        db_table = 'authors'


class Category(models.Model):
    """Category model for article classification"""
    name = models.CharField(max_length=50)
    description = models.TextField(blank=True)

    class Meta:
        db_table = 'categories'


class Article(models.Model):
    """Article model for CMS content"""
    title = models.CharField(max_length=200)
    content = models.TextField()
    author = models.ForeignKey(Author, on_delete=models.CASCADE)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    tags = models.CharField(max_length=200)
    published_date = models.DateField()
    views = models.IntegerField(default=0)
    likes = models.IntegerField(default=0)
    is_featured = models.BooleanField(default=False)

    class Meta:
        db_table = 'articles'

    # A whitelist of fields that are safe to sort by.
    # This prevents injection into the ORDER BY clause.
    # It also includes related fields for more complex sorting.
    _ALLOWED_SORT_FIELDS = {
        'title', 'published_date', 'views', 'likes',
        'author__name', 'category__name'
    }

    # A dictionary mapping friendly names to complex, safe ORM expressions.
    # This prevents SQL injection in SELECT clauses.
    _ALLOWED_COMPUTED_COLUMNS = {
        'engagement_rate': ExpressionWrapper(
            (F('likes') + F('views')) / 2.0,
            output_field=FloatField()
        ),
        'like_to_view_ratio': ExpressionWrapper(
            F('likes') * 1.0 / F('views'),
            output_field=FloatField()
        )
    }

    # A whitelist of related models that are safe to join.
    # This prevents joining arbitrary tables.
    _ALLOWED_RELATED_TABLES = {
        'articlestats', 'author', 'category'
    }

    @classmethod
    def get_article_stats_by_field(cls, sort_field):
        """
        Get article statistics sorted by specified field.

        Args:
            sort_field: A field name from a predefined whitelist to sort by.
                        Prefix with '-' for descending order.

        Returns:
            QuerySet of articles sorted by the specified field.

        Raises:
            ValueError: If the sort_field is not in the allowed list.
        """
        base_field = sort_field.lstrip('-')
        if base_field not in cls._ALLOWED_SORT_FIELDS:
            raise ValueError(f"Invalid sort field: {sort_field}")
        return cls.objects.order_by(sort_field)

    @classmethod
    def get_filtered_articles(cls, filters):
        """
        Get articles matching a set of filters.

        Args:
            filters: A dictionary of filter conditions to apply,
                     e.g., {'author__name': 'Alice', 'is_featured': True}

        Returns:
            QuerySet of articles matching the conditions.
        """
        return cls.objects.filter(**filters)

    @classmethod
    def get_articles_with_computed_column(cls, column_name, expression_key):
        """
        Get articles with a dynamically computed column from a safe list.

        Args:
            column_name: The desired name for the new annotated column.
            expression_key: The key for a predefined, safe ORM expression.

        Returns:
            QuerySet with an additional computed column.

        Raises:
            ValueError: If the expression_key is not in the allowed list.
        """
        if expression_key not in cls._ALLOWED_COMPUTED_COLUMNS:
            raise ValueError(f"Invalid expression key: {expression_key}")

        expression = cls._ALLOWED_COMPUTED_COLUMNS[expression_key]
        return cls.objects.annotate(**{column_name: expression})

    @classmethod
    def get_articles_with_extra_table(cls, related_table_name):
        """
        Get articles with data joined from a whitelisted related table.

        Args:
            related_table_name: The name of a whitelisted related model.

        Returns:
            QuerySet with data from the joined table included efficiently.

        Raises:
            ValueError: If the related_table_name is not in the allowed list.
        """
        if related_table_name not in cls._ALLOWED_RELATED_TABLES:
            raise ValueError(f"Invalid related table: {related_table_name}")

        # select_related is the safe and efficient way to perform SQL joins
        # for foreign key and one-to-one relationships.
        return cls.objects.select_related(related_table_name)


class ArticleStats(models.Model):
    """Article statistics aggregation model"""
    article = models.OneToOneField(Article, on_delete=models.CASCADE)
    total_views = models.IntegerField(default=0)
    unique_visitors = models.IntegerField(default=0)
    avg_read_time = models.FloatField(default=0.0)
    last_viewed = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'article_stats'