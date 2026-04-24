"""
Analytics module for article CMS system.
Provides reporting and statistical analysis on article data.
"""

from django.db import models
from django.db.models import F, Value, ExpressionWrapper, IntegerField, FloatField, Q


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

    @classmethod
    def get_article_stats_by_field(cls, sort_field):
        allowed_fields = {
            "title", "published_date", "views", "likes", "is_featured"
        }
        if sort_field.lstrip("-") not in allowed_fields:
            raise ValueError("Invalid sort field")
        return cls.objects.all().order_by(sort_field)

    @classmethod
    def get_filtered_articles(cls, where_condition):
        if not isinstance(where_condition, dict):
            raise ValueError("where_condition must be a dict of filters")
        return cls.objects.filter(**where_condition)

    @classmethod
    def get_articles_with_computed_column(cls, column_name, expression):
        allowed_expressions = {
            "views_plus_likes": ExpressionWrapper(F("views") + F("likes"), output_field=IntegerField()),
            "engagement_score": ExpressionWrapper(
                (F("likes") * 2 + F("views")) / Value(1.0),
                output_field=FloatField()
            ),
        }
        if expression not in allowed_expressions:
            raise ValueError("Invalid expression")

        return cls.objects.annotate(**{column_name: allowed_expressions[expression]})

    @classmethod
    def get_articles_with_extra_table(cls, extra_table, join_condition):
        if extra_table == "author":
            return cls.objects.select_related("author")
        elif extra_table == "category":
            return cls.objects.select_related("category")
        else:
            raise ValueError("Invalid table requested")


class ArticleStats(models.Model):
    """Article statistics aggregation model"""
    article = models.OneToOneField(Article, on_delete=models.CASCADE)
    total_views = models.IntegerField(default=0)
    unique_visitors = models.IntegerField(default=0)
    avg_read_time = models.FloatField(default=0.0)
    last_viewed = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'article_stats'